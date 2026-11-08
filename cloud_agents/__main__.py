"""Run from project5: python -m cloud_agents --help."""
from __future__ import annotations
import argparse
import copy
import importlib.util
import json
import os
import sys
from dotenv import load_dotenv
from .core import ROOT, Run, Approvals, load_config, redact
from .checks import inspect_website, verify_public
from .aws_tools import AWS
from .agents import AGENTS
from .model import OpenAIResponses, run_agent

REQUEST = ('Deploy and verify a five-page static website using S3, CloudFront with OAC, ACM, and Route 53. '
           'Use the custom domain over HTTPS, redirect HTTP to HTTPS, deny direct anonymous S3 object access, '
           'and record evidence. Identify missing prerequisites and diagnose observed failures without inventing results.')

def workflow(config, run, aws, mode):
    provider = OpenAIResponses()  # Missing key fails explicitly; no fake/offline-agent fallback.
    evidence = {}
    def remember(name, fn):
        def invoke():
            result=fn()
            evidence[name]=result
            run.artifact(name+'.json',result)
            return result
        return invoke
    tools = {
        'inspect_website': {'description':'Read local static website files; validate required pages, links, and inventory hashes.',
                            'call':remember('website_evidence',lambda:inspect_website(config))},
        'prepare_deployment': {'description':'Compute a fixed S3 upload inventory and CloudFront configuration change plan, without mutations.',
                               'call':remember('deployment_plan',aws.plan)},
        'deploy_website': {'description':'Upload configured files and update only approved CloudFront settings; requires an exact interactive human approval.',
                           'call':remember('deployment_submission',aws.deploy)},
        'verify_public': {'description':'Run real HTTP, HTTPS, certificate, navigation, asset, private S3, DNS delegation, and custom error checks.',
                          'call':remember('public_evidence',lambda:verify_public(config))},
        'inspect_aws': {'description':'Inspect configured S3 public access, bucket policy, CloudFront OAC, ACM, and Route 53 using current AWS credentials. Unknown checks remain unknown.',
                        'call':remember('aws_evidence',aws.inspect)},
        'inspect_failure_state': {'description':'Read the local controlled failure snapshot and latest evidence; does not modify cloud resources.',
            'call':lambda:{'state':aws.failure_state(),'public_evidence':evidence.get('public_evidence'),
                           'aws_evidence':evidence.get('aws_evidence'),
                           'recovery_command':'python -m cloud_agents failure restore (human approval required)'}}}
    handoffs=[]
    for original in AGENTS:
        spec=copy.deepcopy(original)
        if spec['name']=='deployment' and mode=='deploy':
            spec['tools'].append('deploy_website')
            spec['required'].append('deploy_website')
        context={'request':REQUEST,'mode':mode,'configuration':config,
                 'input_artifacts':[h['artifact'] for h in handoffs],
                 'handoffs':handoffs}
        if spec['name']=='security' and mode=='deploy':
            context['propagation_warning']='Changes were just submitted. Report transitional failures honestly; repeat audit after CloudFront is Deployed.'
        if spec['name']=='diagnosis':
            context['measured_evidence']=evidence
        report=run_agent(spec,context,tools,run,provider)
        artifact=spec['name']+'.json'
        # Read the stored artifact back: agent-to-agent exchange is durable JSON, not manual copying.
        stored=json.loads((run.path/artifact).read_text(encoding='utf-8'))
        handoffs.append({'from':spec['name'],'artifact':artifact,'report':stored['report']})
        run.event('handoff',{'from':spec['name'],'to':AGENTS[len(handoffs)]['name'] if len(handoffs)<len(AGENTS) else 'human',
                             'artifact':artifact})
    passed=bool(evidence.get('public_evidence',{}).get('passed') and evidence.get('aws_evidence',{}).get('passed'))
    run.artifact('workflow_summary.json',{'passed':passed,'mode':mode,'agent_count':4,'model':provider.model,
        'note':'Pass is computed from deterministic evidence, not from LLM assertions.',
        'public_passed':evidence.get('public_evidence',{}).get('passed'),
        'aws_passed':evidence.get('aws_evidence',{}).get('passed'), 'handoffs':[h['artifact'] for h in handoffs]})
    return 0 if passed else 2

def main(argv=None):
    load_dotenv(ROOT/'.env',override=False)
    parser=argparse.ArgumentParser(description='CSCE 412 scoped multi-agent cloud website project')
    subs=parser.add_subparsers(dest='command',required=True)
    subs.add_parser('doctor',help='Check local prerequisites without displaying secrets')
    subs.add_parser('site',help='Validate local files without cloud or LLM calls')
    subs.add_parser('verify',help='Real public checks; no API key or AWS credentials needed')
    subs.add_parser('inspect',help='Authenticated read-only AWS configuration checks')
    subs.add_parser('plan',help='Show deterministic deployment plan without AWS changes')
    subs.add_parser('deploy',help='Repeatable website upload and CloudFront configuration, with approval')
    subs.add_parser('status',help='Read current CloudFront deployment status')
    agent=subs.add_parser('workflow',help='Run all four real LLM agents')
    agent.add_argument('--mode',choices=['audit','deploy'],default='audit')
    failure=subs.add_parser('failure',help='Controlled reversible default-root experiment')
    failure.add_argument('action',choices=['status','break','restore'])
    dns=subs.add_parser('dns',help='Prepare Route 53 zone and records; registrar delegation remains manual')
    dns.add_argument('action',choices=['plan','prepare'])
    args=parser.parse_args(argv)
    config=load_config()
    if args.command=='doctor':
        from boto3 import Session
        try:
            credentials=Session(profile_name=os.getenv('AWS_PROFILE') or None).get_credentials()
            aws_present=credentials is not None
        except Exception:
            aws_present=False
        print(json.dumps({'python':sys.version.split()[0], 'openai_key_present':bool(os.getenv('OPENAI_API_KEY')),
            'model':os.getenv('OPENAI_MODEL','gpt-4.1-mini'),'aws_credentials_locatable':aws_present,
            'note':'Presence does not prove API billing, IAM permissions, or credential validity.'},indent=2))
        return 0
    run=Run(args.command)
    aws=AWS(config,run,Approvals(run))
    try:
        if args.command=='workflow':
            return workflow(config,run,aws,args.mode)
        if args.command=='site':
            result=inspect_website(config)
        elif args.command=='verify':
            result=verify_public(config)
        elif args.command=='inspect':
            result=aws.inspect()
        elif args.command=='plan':
            result=aws.plan()
        elif args.command=='deploy':
            result=aws.deploy()
        elif args.command=='status':
            distribution=aws.client('cloudfront').get_distribution(Id=config['distribution_id'])['Distribution']
            result={'status':distribution['Status'],'domain':distribution['DomainName'],
                    'failure_state':aws.failure_state()}
        elif args.command=='failure':
            result={'status':aws.failure_state,'break':aws.break_root,'restore':aws.restore_root}[args.action]()
        elif args.command=='dns':
            result=aws.dns_plan() if args.action=='plan' else aws.prepare_dns()
        run.artifact('result.json',result)
        print(json.dumps(redact(result),indent=2))
        return 2 if result.get('passed') is False else 0
    except Exception as exc:
        run.event('run_failed',{'error':type(exc).__name__,'message':str(exc)})
        return 1
    finally:
        print('Evidence directory: '+str(run.path))

if __name__=='__main__':
    raise SystemExit(main())

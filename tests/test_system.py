"""Unit tests use explicitly simulated responses; these are NOT demo execution logs."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from cloud_agents.core import ROOT, Run, Approvals, ApprovalRequired, load_config, redact
from cloud_agents.checks import inspect_website
from cloud_agents.model import run_agent, REPORT_SCHEMA
from cloud_agents.aws_tools import AWS
from cloud_agents.agents import AGENTS
from jsonschema import validate

REPORT={'summary':'Unit test simulation','findings':[],'next_steps':[],'tasks':[],'limitations':['Mock provider; not live LLM evidence']}
def final():
    return {'output':[{'type':'message','role':'assistant','content':[{'type':'output_text','text':json.dumps(REPORT)}]}]}
def call(name,arguments='{}'):
    return {'output':[{'type':'function_call','name':name,'arguments':arguments,'call_id':'test-call'}]}
class Provider:
    model='UNIT-TEST-SIMULATION'
    def __init__(self,responses):
        self.responses=iter(responses)
        self.requests=[]
    def respond(self,**kwargs):
        self.requests.append(kwargs)
        return next(self.responses)

class SystemTests(unittest.TestCase):
    def setUp(self):
        (ROOT/'outputs').mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'outputs')
        self.run=Run('UNIT TEST SIMULATION',parent=self.temp.name)
        self.config=load_config()
    def tearDown(self): self.temp.cleanup()
    def test_website_links_and_five_pages(self):
        result=inspect_website(self.config)
        self.assertTrue(result['passed'],result['problems'])
        self.assertGreaterEqual(len(self.config['pages']),5)
    def test_report_schema_rejects_unstructured_output(self):
        from jsonschema import ValidationError
        with self.assertRaises(ValidationError): validate({'summary':'missing required fields'},REPORT_SCHEMA)
    def test_four_distinct_agent_roles(self):
        self.assertEqual(len({s['name'] for s in AGENTS}),4)
        self.assertEqual(len({s['instructions'] for s in AGENTS}),4)
    def test_model_selected_tool_is_executed(self):
        tool=Mock(return_value={'passed':True})
        spec={'name':'test','instructions':'test','tools':['inspect'],'required':['inspect']}
        result=run_agent(spec,{}, {'inspect':{'description':'test','call':tool}},self.run,
            Provider([call('inspect'),final()]))
        tool.assert_called_once_with()
        self.assertEqual(result,REPORT)
    def test_deployment_is_exposed_only_after_plan(self):
        provider=Provider([call('prepare_deployment'),call('deploy_website'),final()])
        spec={'name':'test','instructions':'test','tools':['prepare_deployment','deploy_website'],
              'required':['prepare_deployment','deploy_website']}
        tools={name:{'description':'test','call':Mock(return_value={})} for name in spec['tools']}
        run_agent(spec,{},tools,self.run,provider)
        self.assertEqual([t['name'] for t in provider.requests[0]['tools']],['prepare_deployment'])
        self.assertEqual([t['name'] for t in provider.requests[1]['tools']],['deploy_website'])
        self.assertEqual(provider.requests[0]['tool_choice'],'required')
        self.assertEqual(provider.requests[1]['tool_choice'],'required')
        self.assertEqual(provider.requests[2]['tool_choice'],'auto')
    def test_unapproved_tool_and_arguments_not_executed(self):
        tool=Mock(return_value={})
        spec={'name':'test','instructions':'test','tools':['inspect'],'required':['inspect']}
        run_agent(spec,{}, {'inspect':{'description':'test','call':tool}},self.run,
            Provider([call('shell'),call('inspect','{"command":"anything"}'),call('inspect'),final()]))
        tool.assert_called_once()
    def test_missing_tool_rejected_then_feedback(self):
        tool=Mock(return_value={})
        spec={'name':'test','instructions':'test','tools':['inspect'],'required':['inspect']}
        run_agent(spec,{}, {'inspect':{'description':'test','call':tool}},self.run,
            Provider([final(),call('inspect'),final()]))
        events=(self.run.path/'events.jsonl').read_text()
        self.assertIn('validation_feedback',events)
    def test_failed_tool_cannot_satisfy_required_tool(self):
        spec={'name':'test','instructions':'test','tools':['inspect'],'required':['inspect']}
        with self.assertRaises(RuntimeError):
            run_agent(spec,{}, {'inspect':{'description':'test','call':Mock(side_effect=RuntimeError('failed'))}},
                self.run,Provider([call('inspect'),final(),final(),final()]))
    def test_approval_is_exact_and_default_deny(self):
        with patch('builtins.input',return_value='yes'):
            with self.assertRaises(ApprovalRequired): Approvals(self.run).require('deploy',{})
        with patch('builtins.input',return_value='APPROVE deploy'):
            Approvals(self.run).require('deploy',{})
    def test_secret_redaction(self):
        with patch.dict(os.environ,{'OPENAI_API_KEY':'secret-for-testing-only'}):
            self.assertEqual(redact({'key':'secret-for-testing-only'})['key'],'[REDACTED]')
    def test_restore_preserves_unrelated_settings_and_uses_fresh_etag(self):
        aws=AWS(self.config,self.run,Mock())
        state_path=Path(self.temp.name)/'failure.json'
        state_path.write_text(json.dumps({'active':True,'distribution_id':self.config['distribution_id'],
            'original_root':'index.html','broken_root':'missing.html'}))
        cf=Mock()
        aws.client=Mock(return_value=cf)
        aws.distribution=Mock(return_value={'ETag':'fresh','DistributionConfig':{
            'DefaultRootObject':'missing.html','Comment':'preserve me'}})
        with patch.object(AWS,'state_path',new_callable=lambda:property(lambda _:state_path)):
            aws.restore_root()
        kwargs=cf.update_distribution.call_args.kwargs
        self.assertEqual(kwargs['IfMatch'],'fresh')
        self.assertEqual(kwargs['DistributionConfig']['Comment'],'preserve me')
        self.assertEqual(kwargs['DistributionConfig']['DefaultRootObject'],'index.html')
    def test_restore_refuses_unrelated_root_change(self):
        aws=AWS(self.config,self.run,Mock())
        state_path=Path(self.temp.name)/'failure.json'
        state_path.write_text(json.dumps({'active':True,'distribution_id':self.config['distribution_id'],
            'original_root':'index.html','broken_root':'missing.html'}))
        aws.distribution=Mock(return_value={'ETag':'fresh','DistributionConfig':{'DefaultRootObject':'other.html'}})
        with patch.object(AWS,'state_path',new_callable=lambda:property(lambda _:state_path)):
            with self.assertRaises(ValueError): aws.restore_root()
    def test_account_mismatch_cannot_leave_cached_session(self):
        aws=AWS(self.config,self.run,Mock())
        session=Mock()
        session.client.return_value.get_caller_identity.return_value={'Account':'000000000000'}
        with patch('cloud_agents.aws_tools.boto3.Session',return_value=session):
            for _ in range(2):
                with self.assertRaises(ValueError): aws.client('s3')
                self.assertIsNone(aws._session)
    def test_root_identity_is_refused(self):
        aws=AWS(self.config,self.run,Mock())
        session=Mock()
        session.client.return_value.get_caller_identity.return_value={
            'Account':self.config['account_id'],'Arn':f"arn:aws:iam::{self.config['account_id']}:root"}
        with patch('cloud_agents.aws_tools.boto3.Session',return_value=session):
            with self.assertRaises(ValueError):aws.client('s3')
        self.assertIsNone(aws._session)
    def test_deploy_denied_before_upload_or_update(self):
        approval=Mock()
        approval.require.side_effect=ApprovalRequired('not approved')
        aws=AWS(self.config,self.run,approval)
        cf=Mock()
        aws.client=Mock(return_value=cf)
        aws.failure_state=Mock(return_value={'active':False})
        aws.distribution=Mock(return_value={'ETag':'current','DistributionConfig':{
            'DefaultCacheBehavior':{},'Aliases':{'Quantity':0}}})
        with self.assertRaises(ApprovalRequired): aws.deploy()
        cf.put_object.assert_not_called()
        cf.update_distribution.assert_not_called()
    def test_unknown_aws_configuration_cannot_pass(self):
        aws=AWS(self.config,self.run,Mock())
        aws.client=Mock(side_effect=RuntimeError('credentials unavailable'))
        result=aws.inspect()
        self.assertFalse(result['passed'])
        self.assertTrue(any(c['passed'] is None for c in result['checks']))
    def test_console_exact_arnlike_bucket_policy_is_recognized(self):
        aws=AWS(self.config,self.run,Mock())
        client=Mock()
        client.get_bucket_policy_status.return_value={'PolicyStatus':{'IsPublic':False}}
        source=f"arn:aws:cloudfront::{self.config['account_id']}:distribution/{self.config['distribution_id']}"
        statement={'Effect':'Allow','Principal':{'Service':'cloudfront.amazonaws.com'},
            'Action':'s3:GetObject','Resource':f"arn:aws:s3:::{self.config['bucket']}/*",
            'Condition':{'ArnLike':{'AWS:SourceArn':source}}}
        client.get_bucket_policy.return_value={'Policy':json.dumps({'Statement':[statement]})}
        aws.client=Mock(return_value=client)
        result=aws.inspect()
        policy=next(c for c in result['checks'] if c['name']=='s3_policy')
        self.assertTrue(policy['passed'])
        statement['Condition']['ArnLike']['AWS:SourceArn']=source+'*'
        client.get_bucket_policy.return_value={'Policy':json.dumps({'Statement':[statement]})}
        result=aws.inspect()
        self.assertFalse(next(c for c in result['checks'] if c['name']=='s3_policy')['passed'])

if __name__=='__main__': unittest.main()

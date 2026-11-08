"""Scoped AWS operations for this configured project, with explicit approvals."""
from __future__ import annotations
import copy
import hashlib
import json
import mimetypes
from pathlib import Path
import boto3
from botocore.config import Config
from .checks import inspect_website
from .core import ROOT, now, save_json

class AWS:
    def __init__(self, config, run, approvals):
        self.config, self.run, self.approvals = config, run, approvals
        self._session = None

    def client(self, service, region=None):
        if service not in {'s3','cloudfront','acm','route53'}:
            raise ValueError('AWS service not allowed')
        if self._session is None:
            import os
            session = boto3.Session(profile_name=os.getenv('AWS_PROFILE') or None,
                                          region_name=self.config['region'])
            # STS is used only to verify the current identity, never to provision services.
            identity = session.client('sts', config=Config(connect_timeout=10, read_timeout=20,
                retries={'max_attempts': 1})).get_caller_identity()
            if identity['Account'] != self.config['account_id']:
                raise ValueError('AWS identity belongs to a different account; operation refused')
            if identity.get('Arn','').endswith(':root'):
                raise ValueError('Root credentials are not allowed for agent tools; use the restricted project5-agent profile')
            self._session = session
            self.run.event('aws_identity_checked', {'account': identity['Account']})
        return self._session.client(service, region_name=region or self.config['region'],
            config=Config(connect_timeout=10, read_timeout=25, retries={'max_attempts': 2}))

    def distribution(self):
        return self.client('cloudfront').get_distribution_config(Id=self.config['distribution_id'])

    def inspect(self):
        rows = []
        def check(name, fn):
            try:
                passed, evidence = fn()
                rows.append({'name': name, 'passed': bool(passed), 'evidence': evidence})
            except Exception as exc:
                rows.append({'name': name, 'passed': None, 'evidence': {'error': type(exc).__name__}})
        def distribution():
            data = self.distribution()['DistributionConfig']
            origins = data.get('Origins',{}).get('Items',[])
            matches = [o for o in origins if o.get('DomainName') == f"{self.config['bucket']}.s3.{self.config['region']}.amazonaws.com"
                       or o.get('DomainName') == f"{self.config['bucket']}.s3.amazonaws.com"]
            behavior = data['DefaultCacheBehavior']
            origin = next((o for o in matches if o['Id'] == behavior['TargetOriginId']), None)
            oac = self.client('cloudfront').get_origin_access_control(Id=origin['OriginAccessControlId'])['OriginAccessControl']['OriginAccessControlConfig'] if origin and origin.get('OriginAccessControlId') else {}
            aliases = data.get('Aliases',{}).get('Items',[])
            ok = (data.get('Enabled') and data.get('DefaultRootObject') == 'index.html'
                  and self.config['domain'] in aliases and behavior.get('ViewerProtocolPolicy') == 'redirect-to-https'
                  and all(b.get('ViewerProtocolPolicy') == 'redirect-to-https' for b in data.get('CacheBehaviors',{}).get('Items',[]))
                  and oac.get('SigningBehavior') == 'always' and oac.get('SigningProtocol') == 'sigv4'
                  and data.get('ViewerCertificate',{}).get('ACMCertificateArn') == self.config['certificate_arn'])
            return ok, {'enabled': data.get('Enabled'), 'default_root':data.get('DefaultRootObject'),
                'aliases': aliases, 'viewer_protocol': behavior.get('ViewerProtocolPolicy'),
                'origin_domain': origin.get('DomainName') if origin else None,
                'oac_signing': oac.get('SigningBehavior'), 'oac_protocol': oac.get('SigningProtocol'),
                'certificate_arn':data.get('ViewerCertificate',{}).get('ACMCertificateArn')}
        check('cloudfront_configuration', distribution)
        def block_public():
            data = self.client('s3').get_public_access_block(Bucket=self.config['bucket'])['PublicAccessBlockConfiguration']
            return all(data.get(k) is True for k in ['BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets']), data
        check('s3_block_public_access', block_public)
        def policy():
            s3 = self.client('s3')
            public = s3.get_bucket_policy_status(Bucket=self.config['bucket'])['PolicyStatus']['IsPublic']
            statements = json.loads(s3.get_bucket_policy(Bucket=self.config['bucket'])['Policy']).get('Statement',[])
            if isinstance(statements,dict):
                statements=[statements]
            source = f"arn:aws:cloudfront::{self.config['account_id']}:distribution/{self.config['distribution_id']}"
            found = False
            for row in statements:
                principal = row.get('Principal',{})
                # An exact ARN under ArnLike is equivalent here to ArnEquals:
                # no wildcard is accepted. The console currently emits ArnLike.
                condition_blocks = row.get('Condition',{})
                bounds = []
                for operator in ('StringEquals','ArnEquals','ArnLike','StringLike'):
                    condition = condition_blocks.get(operator,{})
                    bound = condition.get('AWS:SourceArn') or condition.get('aws:SourceArn')
                    bounds.extend(bound if isinstance(bound,list) else [bound])
                actions = row.get('Action',[])
                actions = [actions] if isinstance(actions,str) else actions
                resources = row.get('Resource',[])
                resources = [resources] if isinstance(resources,str) else resources
                if (row.get('Effect') == 'Allow' and isinstance(principal,dict)
                    and principal.get('Service') == 'cloudfront.amazonaws.com' and source in bounds
                    and 's3:GetObject' in actions and f"arn:aws:s3:::{self.config['bucket']}/*" in resources):
                    found=True
            return not public and found, {'is_public': public, 'distribution_scoped_oac_statement': found}
        check('s3_policy', policy)
        def cert():
            data = self.client('acm','us-east-1').describe_certificate(CertificateArn=self.config['certificate_arn'])['Certificate']
            return data['Status']=='ISSUED' and self.config['domain'] in data.get('SubjectAlternativeNames',[]), {
                'status':data['Status'],'names':data.get('SubjectAlternativeNames',[]),'expires':str(data.get('NotAfter'))}
        check('acm_certificate', cert)
        def dns():
            zone = self.config.get('hosted_zone_id')
            if not zone:
                return False, {'reason':'hosted_zone_id is not configured; prepare and delegate Route 53 first'}
            data = self.client('route53').get_hosted_zone(Id=zone)
            records = self.client('route53').list_resource_record_sets(HostedZoneId=zone)['ResourceRecordSets']
            apex = [r for r in records if r['Name'].rstrip('.')==self.config['domain'] and r['Type']=='A']
            return (data['HostedZone']['Name'].rstrip('.')==self.config['domain']
                and any(r.get('AliasTarget',{}).get('DNSName','').rstrip('.') == self.config['distribution_domain'] for r in apex)), {
                'zone_id':zone, 'nameservers':data.get('DelegationSet',{}).get('NameServers'), 'apex_records':apex}
        check('route53_configuration', dns)
        return {'time':now(), 'passed':all(r['passed'] is True for r in rows), 'checks':rows}

    def plan(self):
        inventory = inspect_website(self.config)
        return {'website':inventory, 'target': {'bucket': self.config['bucket'],
            'distribution_id':self.config['distribution_id'], 'domain':self.config['domain']},
            'actions':['Upload these exact website files without deleting other objects',
                       'Set index.html, domain certificate, HTTP redirects, and custom 403/404 responses',
                       'Invalidate CloudFront cache'],
            'limits':['Does not change DNS, bucket policies, IAM, or origin permissions',
                      'Uses an existing distribution and bucket; initial provisioning is documented separately'],
            'approval_required':True}

    def deploy(self):
        if self.failure_state().get('active'):
            raise RuntimeError('Restore the controlled failure before deploying')
        plan = self.plan()
        if not plan['website']['passed']:
            raise ValueError('Local website validation failed')
        cf = self.client('cloudfront')
        current = self.distribution()
        cfg = copy.deepcopy(current['DistributionConfig'])
        # Do not accidentally remove another domain from a shared distribution.
        aliases = cfg.get('Aliases',{}).get('Items',[])
        if any(name != self.config['domain'] for name in aliases):
            raise ValueError('Distribution has other aliases; review manually before using this scoped deployment')
        cfg['DefaultRootObject']='index.html'
        cfg['Aliases']={'Quantity':1,'Items':[self.config['domain']]}
        cfg['ViewerCertificate']={'ACMCertificateArn':self.config['certificate_arn'],
            'SSLSupportMethod':'sni-only','MinimumProtocolVersion':'TLSv1.2_2021'}
        cfg['DefaultCacheBehavior']['ViewerProtocolPolicy']='redirect-to-https'
        for behavior in cfg.get('CacheBehaviors',{}).get('Items',[]):
            behavior['ViewerProtocolPolicy']='redirect-to-https'
        errors = {row['ErrorCode']:row for row in cfg.get('CustomErrorResponses',{}).get('Items',[])}
        for status in (403,404):
            errors[status]={'ErrorCode':status,'ResponsePagePath':'/404.html','ResponseCode':'404','ErrorCachingMinTTL':0}
        cfg['CustomErrorResponses']={'Quantity':len(errors),'Items':list(errors.values())}
        plan['settings']={'default_root':'index.html','viewer_protocol':'redirect-to-https',
            'custom_errors':cfg['CustomErrorResponses'], 'certificate_arn':self.config['certificate_arn']}
        self.approvals.require('deploy',plan)
        if inspect_website(self.config)['files'] != plan['website']['files']:
            raise ValueError('Website changed after approval; re-run for a fresh approval')
        s3 = self.client('s3')
        for row in plan['website']['files']:
            path = ROOT/self.config['website_directory']/row['key']
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest()!=row['sha256']:
                raise ValueError('Website file changed after approval')
            mime = mimetypes.guess_type(path.name)[0] or 'application/octet-stream'
            s3.put_object(Bucket=self.config['bucket'], Key=row['key'], Body=data,
                          ContentType=mime, CacheControl='public,max-age=300', ServerSideEncryption='AES256')
            self.run.event('s3_uploaded',{'key':row['key'],'sha256':row['sha256']})
        # ETag prevents overwriting a concurrent distribution change.
        cf.update_distribution(Id=self.config['distribution_id'],IfMatch=current['ETag'],DistributionConfig=cfg)
        invalidation = cf.create_invalidation(DistributionId=self.config['distribution_id'],
            InvalidationBatch={'Paths':{'Quantity':1,'Items':['/*']},'CallerReference':self.run.id})
        return {'submitted':True,'distribution_id':self.config['distribution_id'],
                'invalidation_id':invalidation['Invalidation']['Id'],
                'note':'AWS accepted the changes. Wait for deployment, then verify; acceptance is not proof of propagation.'}

    @property
    def state_path(self):
        return ROOT/'.state'/f"failure-{self.config['distribution_id']}.json"

    def failure_state(self):
        if not self.state_path.exists():
            return {'active':False,'reason':'No saved controlled failure snapshot'}
        state = json.loads(self.state_path.read_text(encoding='utf-8'))
        # Expose only the controlled field, never the full CloudFront config.
        return {k:state[k] for k in ['active','phase','original_root','broken_root','distribution_id','created_at'] if k in state}

    def break_root(self):
        if self.state_path.exists() and self.failure_state().get('active'):
            raise RuntimeError('Failure snapshot already active; restore first')
        cf = self.client('cloudfront')
        if cf.get_distribution(Id=self.config['distribution_id'])['Distribution']['Status']!='Deployed':
            raise RuntimeError('Wait for distribution status Deployed before the experiment')
        current = self.distribution()
        cfg = copy.deepcopy(current['DistributionConfig'])
        if cfg.get('DefaultRootObject')!='index.html':
            raise ValueError('Baseline default root must be index.html')
        broken = '__project5_controlled_missing_root__.html'
        s3 = self.client('s3')
        from botocore.exceptions import ClientError
        try:
            s3.head_object(Bucket=self.config['bucket'],Key=broken)
        except ClientError as exc:
            if exc.response['Error']['Code'] not in ('404','NoSuchKey','NotFound'):
                raise
        else:
            raise ValueError('Controlled missing object already exists; no change applied')
        self.approvals.require('break-root',{'distribution':self.config['distribution_id'],
            'change':{'DefaultRootObject':broken},'effect':'Homepage / will fail after propagation; explicit /index.html remains accessible',
            'recovery':'python -m cloud_agents failure restore; original root is saved before mutation',
            'warning':'This temporarily disrupts your live homepage. Restore immediately after recording evidence.'})
        state={'active':True,'phase':'prepared','distribution_id':self.config['distribution_id'],
            'original_root':'index.html','broken_root':broken,'created_at':now()}
        save_json(self.state_path,state)
        cfg['DefaultRootObject']=broken
        cf.update_distribution(Id=self.config['distribution_id'],IfMatch=current['ETag'],DistributionConfig=cfg)
        state['phase']='submitted'
        save_json(self.state_path,state)
        cf.create_invalidation(DistributionId=self.config['distribution_id'],InvalidationBatch={
            'Paths':{'Quantity':1,'Items':['/']},'CallerReference':self.run.id+'-break'})
        return {'submitted':True,**self.failure_state()}

    def restore_root(self):
        if not self.state_path.exists():
            raise ValueError('No saved failure snapshot')
        state = json.loads(self.state_path.read_text(encoding='utf-8'))
        if not state.get('active') or state.get('distribution_id')!=self.config['distribution_id']:
            raise ValueError('No matching active failure')
        current = self.distribution()
        cfg = copy.deepcopy(current['DistributionConfig'])
        # Restore just the changed field, preserving unrelated changes made meanwhile.
        if cfg.get('DefaultRootObject') not in (state['broken_root'], state['original_root']):
            raise ValueError('Default root changed outside this experiment; refusing to overwrite')
        self.approvals.require('restore-root',{'distribution':self.config['distribution_id'],
            'from':cfg.get('DefaultRootObject'),'to':state['original_root']})
        cf = self.client('cloudfront')
        if cfg.get('DefaultRootObject')!=state['original_root']:
            cfg['DefaultRootObject']=state['original_root']
            cf.update_distribution(Id=self.config['distribution_id'],IfMatch=current['ETag'],DistributionConfig=cfg)
        cf.create_invalidation(DistributionId=self.config['distribution_id'],InvalidationBatch={
            'Paths':{'Quantity':1,'Items':['/']},'CallerReference':self.run.id+'-restore'})
        state['active']=False
        state['phase']='restoration_submitted'
        save_json(self.state_path,state)
        return {'submitted':True,'note':'Wait for deployment and run verification before claiming recovery.'}

    def dns_plan(self):
        c = self.config
        records=[{'Name':c['domain']+'.','Type':'A','AliasTarget':{'HostedZoneId':'Z2FDTNDATAQYW2',
            'DNSName':c['distribution_domain']+'.','EvaluateTargetHealth':False}},
            {'Name':c['validation_name'],'Type':'CNAME','TTL':300,'ResourceRecords':[{'Value':c['validation_value']}]}]
        return {'domain':c['domain'],'records':records,'note':'Creates or reuses one public Route 53 zone. Registrar remains Namecheap. Copy all other existing DNS records before changing nameservers. Route 53 hosted zones and queries have charges.'}

    def prepare_dns(self):
        route53 = self.client('route53')
        zones=[]
        for page in route53.get_paginator('list_hosted_zones').paginate():
            zones.extend(z for z in page['HostedZones'] if z['Name'].rstrip('.')==self.config['domain'] and not z['Config']['PrivateZone'])
        configured=self.config.get('hosted_zone_id','').replace('/hostedzone/','')
        if len(zones)>1 and not configured:
            raise ValueError('Multiple matching zones; explicitly configure hosted_zone_id')
        zone = next((z for z in zones if z['Id'].replace('/hostedzone/','')==configured),None) if configured else (zones[0] if zones else None)
        if configured and zone is None:
            raise ValueError('Configured hosted zone not found for domain')
        plan=self.dns_plan()
        plan['existing_zone']=zone['Id'] if zone else None
        self.approvals.require('prepare-dns',plan)
        if zone is None:
            zone=route53.create_hosted_zone(Name=self.config['domain'],CallerReference=self.run.id,
                HostedZoneConfig={'Comment':'CSCE 412 Project 5','PrivateZone':False})['HostedZone']
        zone_id=zone['Id'].replace('/hostedzone/','')
        # Save immediately so an interrupted retry reuses this zone instead of charging for another.
        self.config['hosted_zone_id']=zone_id
        save_json(ROOT/'config.json',self.config)
        route53.change_resource_record_sets(HostedZoneId=zone_id,ChangeBatch={
            'Comment':'Project 5 CloudFront alias and ACM validation',
            'Changes':[{'Action':'UPSERT','ResourceRecordSet':r} for r in plan['records']]})
        nameservers=route53.get_hosted_zone(Id=zone_id)['DelegationSet']['NameServers']
        return {'zone_id':zone_id,'nameservers':nameservers,'manual_next_step':
            'In Namecheap Domain > Nameservers, select Custom DNS and enter all four nameservers AFTER copying any other required DNS records. Verify DNSSEC DS records are absent or correctly migrated. Do not delete the old Namecheap records yet.'}

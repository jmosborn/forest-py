#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError
import argparse

def get_args():
	description='A DevSecOps tool for cloud auditing and resource discovery'
	parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('layer', metavar='layer', help='The forest layer, or type of resource, to show:\n\nnetwork\ninstances\nips\nlbs\necs\nredis\ns3\niam')
	parser.add_argument('-v', dest='verbose', action='store_true', help='show more details for resources')
	parser.add_argument('--all-regions', '-a', dest='all_regions', action='store_true', help='show all regions')
	parser.add_argument('--all-instances', '-i', dest='all_instances', action='store_true', help='show all instances')
	parser.add_argument('--total', '-t', dest='total', action='store_true', help='only show totals, not details')
	subparsers = parser.add_subparsers()
	subparsers.dest = 'subcommand'
	subparser = subparsers.add_parser("group", help="show IAM by group")
	subparser = subparsers.add_parser("user", help="show IAM by user")
	parser.set_defaults(verbose=False, all_regions=False, all_instances=False, total=False)

	args = parser.parse_args()
	return args

def get_instances(ec2):
	if not args.all_instances:
		filters = [{'Name': 'instance-state-name', 'Values': ['running']}]
	else:
		filters = []
	response = ec2.describe_instances(Filters=filters)
	our_instances = []
	if args.total:
		our_total = 0
		for r in response['Reservations']:
			for i in r['Instances']:
				our_total = our_total + 1
		return our_total
	else:
		for reservation in response['Reservations']:
			for instance in reservation['Instances']:
				our_values = [instance['InstanceId'], instance['InstanceType'], instance['Placement']['AvailabilityZone'], instance['SubnetId'], instance['VpcId'], instance['State']['Name']]
				our_instances.append(' '.join(our_values))
		return our_instances
	return 0

def get_ecs_clusters(ecs):
	response = ecs.list_clusters().get('clusterArns')
	for cluster in response:

		our_cluster = f"cluster: {cluster.split('/')[-1]}"
		print_leaves(our_cluster)

		response = ecs.list_container_instances(cluster=cluster).get('containerInstanceArns')
		if response:
			print_leaves(response, 2)

		response = ecs.list_services(cluster=cluster).get('serviceArns')
		if response:
			for service in response:
				our_service = f"service: {service.split('/')[-1]}"
				print_leaves(our_service, 2)

		response = ecs.list_tasks(cluster=cluster).get('taskArns')
		if response:
			if args.verbose:
				our_tasks = []
				response = ecs.describe_tasks(cluster=cluster, tasks=response)
				for task in response['tasks']:
					our_details=['task:', task['containers'][0]['name'], task['availabilityZone'], '-->'.join([task['lastStatus'], task['desiredStatus']]), task['cpu'], task['memory'], str(task['startedAt'])]
					our_tasks.append(' '.join(our_details))
					print_leaves(our_tasks, 3)
			else:
				for task in response:
					our_task =  f"task: {task.split('/')[-2]}"
					print_leaves(our_task, 3)

def get_albs(alb):
	response = alb.describe_load_balancers()
	for lb in response['LoadBalancers']:
		if args.verbose:
			listeners = alb.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
			our_listeners = []
			for l in listeners['Listeners']:
				our_details = ['listener:', l['Protocol'], str(l['Port'])]
				our_listeners.append(' '.join(our_details))
			tgs = alb.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
			our_tgs = []
			for tg in tgs['TargetGroups']:
				tghealth = alb.describe_target_health(TargetGroupArn=tg['TargetGroupArn']).get('TargetHealthDescriptions')
				our_health = tghealth[0]['TargetHealth']['State']
				our_details = ['targetgroup:', tg['TargetGroupName'], tg['Protocol'], str(tg['Port']), tg['HealthCheckProtocol'], str(tg['HealthCheckPort']), str(tg['HealthCheckEnabled']), tg['TargetType'], our_health]
				our_tgs.append(' '.join(our_details))
			our_azs = []
			for az in lb['AvailabilityZones']:
				our_azs.append(az['ZoneName'])
			our_details = [lb['LoadBalancerName'], ' '.join(our_azs), lb['DNSName']]
			our_lb = ' '.join(our_details)
			print_leaves(our_lb)
			print_leaves(our_listeners, 2)
			print_leaves(our_tgs, 2)
		else:
			print_leaves(lb['LoadBalancerName'])

def get_redis(ecache):
	response = ecache.describe_replication_groups()
	#our_clusters = []
	for group in response['ReplicationGroups']:
		if args.verbose:
			our_group = ' '.join([group['ReplicationGroupId'], group['Status'], f"auto-failover:{group['AutomaticFailover']}", f"multi-az:{group['MultiAZ']}", f"cluster:{group['ClusterEnabled']}", f"{group['ConfigurationEndpoint']['Address']}:{group['ConfigurationEndpoint']['Port']}"])
		else:
			our_group = group['ReplicationGroupId']
		print_leaves(our_group)
		clusters = group['MemberClusters']
		our_clusters = []
		for c in clusters:
			cluster = ecache.describe_cache_clusters(CacheClusterId=c).get('CacheClusters')[0]
			if args.verbose:
				our_details = [cluster['CacheClusterId'], cluster['CacheNodeType'], cluster['Engine'], cluster['CacheClusterStatus'], str(cluster['NumCacheNodes']), cluster['CacheSubnetGroupName'], cluster['ReplicationGroupId'], cluster['PreferredAvailabilityZone']]
			else:
				our_details = [cluster['CacheClusterId']]
			our_cluster = ' '.join(our_details)
			our_clusters.append(our_cluster)
		print_leaves(our_clusters, 2)
		nodegroups = group['NodeGroups']
		if args.verbose:
			for n in nodegroups:
				our_nodegroup = ' '.join([n['NodeGroupId'], n['Status'], n['Slots']])
				print_leaves(our_nodegroup, 2)
			if cluster.get('CacheNodes'):
				our_nodes = []
				for node in cluster['CacheNodes']:
					our_nodes.append(node['CacheNodeId'])
				print_leaves(our_nodes)

def get_vpcs(ec2):
	vpcs = ec2.describe_vpcs().get("Vpcs")
	if args.total:
		return len(vpcs)
	else:
		our_vpcs = []
		for vpc in vpcs:
			our_vpcs.append(vpc['VpcId'])
		return our_vpcs

def get_ips(ec2):
	response = ec2.describe_addresses()
	our_addresses = []
	for address in response.get('Addresses'):
		if args.verbose:
			our_addresses.append(' '.join([address['PublicIp'], address['PrivateIpAddress'], address['InstanceId'], address['AllocationId'], address['AssociationId']]))
		else:
			our_addresses.append(address['PublicIp'])
	if args.total:
		print(region, '\t\t', len(our_addresses))
	else:
		print(region)
		print_leaves(our_addresses)

def get_s3(s3):
	buckets = s3.list_buckets()
	for bucket in buckets['Buckets']:
		location = s3.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
		if not location:
			location = "us-east-1"
		encryption = "yes"
		try:
			e = s3.get_bucket_encryption(Bucket=bucket['Name'])
		except ClientError as error:
			if error.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
				encryption = "no"
		try:
			ls = s3.get_bucket_lifecycle_configuration(Bucket=bucket['Name'])
			lifecycle = len(ls['Rules'])
		except ClientError as error:
			if error.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
				lifecycle = 0
		v = s3.get_bucket_versioning(Bucket=bucket['Name'])
		versioning = "Disabled"
		mfadelete = "Disabled"
		if v.get('Status'):
			versioning = v['Status']
		if v.get('MFADelete'):
			mfadelete = v['MFADelete']
		our_details = [bucket['Name'], f"({location})", f"encryption:{encryption}", f"lifecycle-policies:{lifecycle}", f"versioning:{versioning}", f"mfa-delete:{mfadelete}"]
		our_bucket = ' '.join(our_details)
		print_leaves(our_bucket, 0)

def get_iam(iam):
	if args.subcommand == 'group':
		groups = iam.list_groups()
		for group in groups['Groups']:
			group_name = group['GroupName']
			print_leaves(group_name)
			members = iam.get_group(GroupName=group_name).get('Users')
			for member in members:
				if member.get('PasswordLastUsed'):
					our_details = [member['UserName'], f"created:{str(member['CreateDate'])}", f"password-last-used:{str(member['PasswordLastUsed'])}"]
				else:
					our_details = [member['UserName'], f"created:{str(member['CreateDate'])}"]
				print_leaves(' '.join(our_details), 2)
	elif args.subcommand == 'user':
		users = iam.list_users()
		for user in users['Users']:
			user_name = user['UserName']
			print_leaves(user_name)

def print_leaves(leaves, level = 1):
	if leaves:
		if level == 1:
			spacing = '\t'
		elif level == 2:
			spacing = '\t\t'
		elif level == 0:
			spacing = '-'
		else:
			spacing = '\t\t\t'

		if isinstance(leaves, list):
			for leaf in leaves:
				print(spacing, leaf)
		else:
			print(spacing, leaves)

def print_banner(title):
	banner = f"---------- {title} ----------"
	print(banner)

args = get_args()

ec2 = boto3.client('ec2')

our_regions = []

if args.all_regions:
	response = ec2.describe_regions().get("Regions")

	#response = ec2.describe_availability_zones()
	#print ('Availability Zones:', response ['AvailabilityZones'])

	for region in response:
		our_regions.append(region["RegionName"])
else:
	our_regions.append(ec2.meta.region_name)

if args.layer == "instances":
	print_banner("Instances")
	for region in our_regions:
		ec2 = boto3.client('ec2', region_name=region)
		instances = get_instances(ec2)
		if args.total:
			print(region, '\t\t', instances)
		else:
			print(region)
			print_leaves(instances)
			
elif args.layer == "ips":
	print_banner("IPs")
	for region in our_regions:
		ec2 = boto3.client('ec2', region_name=region)
		get_ips(ec2)
elif args.layer == "lbs":
	print_banner("Load Balancers")
	for region in our_regions:
		print(region)
		albs = boto3.client('elbv2', region_name=region)
		get_albs(albs)
elif args.layer == "redis":
	print_banner("Redis")
	for region in our_regions:
		print(region)
		ecache = boto3.client('elasticache')
		get_redis(ecache)
elif args.layer == "network":
	print_banner("Network")
	for region in our_regions:
		ec2 = boto3.client('ec2', region_name=region)
		vpcs = get_vpcs(ec2)
		if args.total:
			print(region, '\t\t', vpcs)
		else:
			print(region)
			ec2r = boto3.resource('ec2')
			for vpc in vpcs:
				print_leaves(vpc)
				for subnet in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]}]).get("Subnets"):
					our_subnet = f"{subnet['SubnetId']} ({subnet['AvailabilityZone']})"
					print_leaves(our_subnet, 2)
elif args.layer == "ecs":
	print_banner("ECS")
	for region in our_regions:
		print(region)
		ecs = boto3.client('ecs', region_name=region)
		get_ecs_clusters(ecs)
elif args.layer == "s3":
	print_banner("S3")
	s3 = boto3.client('s3', region_name='us-east-1')
	get_s3(s3)
elif args.layer == "iam":
	print_banner("IAM")
	print("Global")
	iam = boto3.client('iam', region_name='us-east-1')
	get_iam(iam)

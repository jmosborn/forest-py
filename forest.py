#!/usr/bin/env python3

import boto3
import argparse

def get_args():
	description='A DevSecOps tool for cloud auditing and resource discovery'
	parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('layer', metavar='layer', help='The forest layer, or type of resource, to show:\n\ninstances\nnetwork\nips\necs\nlbs')
	parser.add_argument('-v', dest='verbose', action='store_true', help='show more details for resources')
	parser.add_argument('--all-regions', '-a', dest='all_regions', action='store_true', help='show all regions')
	parser.add_argument('--all-instances', '-i', dest='all_instances', action='store_true', help='show all instances')
	parser.add_argument('--total', '-t', dest='total', action='store_true', help='only show totals, not details')
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
					print_leaves(task, 2)

def get_vpcs(ec2):
	vpcs = ec2.describe_vpcs().get("Vpcs")
	if args.total:
		return len(vpcs)
	else:
		our_vpcs = []
		for vpc in vpcs:
			our_vpcs.append(vpc['VpcId'])
		return our_vpcs

def print_leaves(leaves, level = 1):
	if leaves:
		if level == 1:
			spacing = '\t'
		elif level == 2:
			spacing = '\t\t'
		else:
			spacing = '\t\t\t'

		if isinstance(leaves, list):
			for leaf in leaves:
				print(spacing, leaf)
		else:
			print(spacing, leaves)

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
	for region in our_regions:
		ec2 = boto3.client('ec2', region_name=region)
		instances = get_instances(ec2)
		if args.total:
			print(region, '\t\t', instances)
		else:
			print(region)
			print_leaves(instances)
			
elif args.layer == "ips":
	for region in our_regions:
		#print(region)
		ec2 = boto3.client('ec2', region_name=region)
		response = ec2.describe_addresses().get("Addresses")
		our_addresses = []
		for address in response:
			our_addresses.append(response("PublicIp"))
		if args.total:
			print(region, '\t\t', len(our_addresses))
		else:
			print(region)
			print_leaves(our_addresses)
elif args.layer == "lbs":
	for region in our_regions:
		elbs = boto3.client('elb', region_name=region)
		response = elbs.describe_load_balancers()
		print(response)
		albs = boto3.client('elbv2', region_name=region)
		response = albs.describe_load_balancers()
		print(response)
elif args.layer == "network":
	for region in our_regions:
		ec2 = boto3.client('ec2', region_name=region)
		vpcs = get_vpcs(ec2)
		if args.total:
			print(region, '\t\t', vpcs)
		else:
			print(region)
			print_leaves(vpcs)
elif args.layer == "ecs":
	for region in our_regions:
		print(region)
		ecs = boto3.client('ecs', region_name=region)
		get_ecs_clusters(ecs)

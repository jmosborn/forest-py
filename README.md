# forest

A read-only DevOps tools for AWS account auditing and resource discovery. Originally written in Go, I'm converting it to Python for various reasons. It just provides and quick way to list resources across zones and regions in an account, in order to see the larger picture of an AWS infrastructure, like seeing a birds-eye view of a forest in various layers.

## Usage

`forest.py <layer> [options]`

`forest.py -h`

## Layers

If an AWS infrastructure is a forest filled with trees, the forest layers are higher-level conceptual organizations of the resources for common purposes and architectures. The following layers are currently supported:

| Layer | Description |
| ----- | ----- |
| network | Show a network layout by vpc and subnet |
| instances | List all instances |
| ips | List all IPs |
| lbs | Show load balancers, listeners, and target groups |
| ecs | Show the ECS infrastructure including clusters, services, and tasks |
| redis | Show elasticache redis clusters and nodes |

## Options

-a/--all-regions

Show resources in all regions, rather than just the default

-i/--all-instances

Show all instances, rather than the default of only running instances

-t/--total

Show totals rather than individual resources

-v

Shows more details about resources, rather than just listening their names

## Authentication

Configure credentials with `aws configure`.

This is a read-only tool; no write access is required. The user must have sufficient read privileges for all the services being queried. To give an IAM user read-only access to all services, use Amazon's ReadOnlyAccess policy.

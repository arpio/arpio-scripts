import boto3
import os
import botocore

def create_sts_client(sts):
    # Clear any existing setting
    if 'AWS_STS_REGIONAL_ENDPOINTS' in os.environ:
        del os.environ['AWS_STS_REGIONAL_ENDPOINTS']
    
    # Handle the different cases
    if sts == "unset":
        print("Setting: unset (environment variable removed)")
    else:
        os.environ['AWS_STS_REGIONAL_ENDPOINTS'] = sts
        print(f"Setting: {sts}")
    
    # Print boto3/botocore versions
    print(f"Boto3 version: {boto3.__version__}")
    print(f"Botocore version: {botocore.__version__}")
    
    # Try with different regions to see the behavior
    print("\nTesting different regions:")
    

    # Test with ap-south-2 (opt-in region)
    sts_client = boto3.client('sts', region_name='ap-south-2')
    print(f"  ap-south-2: {sts_client.meta.endpoint_url}")

    # Test with us-east-1 (original region)
    sts_client = boto3.client('sts', region_name='us-east-1')
    print(f"  us-east-1: {sts_client.meta.endpoint_url}")

        # Test with us-east-1 (original region)
    sts_client = boto3.client('sts', region_name='us-east-2')
    print(f"  us-east-2: {sts_client.meta.endpoint_url}")
    
    sts_client = boto3.client('sts', region_name='ap-southeast-1')
    print(f"  ap-southeast-1: {sts_client.meta.endpoint_url}")

    # Test with no region specified (should default to us-east-1)
    sts_client = boto3.client('sts')
    print(f"  No region: {sts_client.meta.endpoint_url}")

    print("-" * 50)


if __name__ == "__main__":
    # Check for AWS config file settings
    config_locations = [
        os.path.expanduser('~/.aws/config'),
        os.path.expanduser('~/.aws/credentials')
    ]
    
    print("Checking for AWS config files:")
    for loc in config_locations:
        if os.path.exists(loc):
            print(f"  Found: {loc}")
            # Check if sts_regional_endpoints is set in the file
            with open(loc, 'r') as f:
                content = f.read()
                if 'sts_regional_endpoints' in content:
                    print(f"    WARNING: sts_regional_endpoints found in {loc}")
    print("-" * 50)
    
    create_sts_client("legacy")
    create_sts_client("regional")
    create_sts_client("unset")
import boto3

user = "testUser"
group_name = 'admin'
s3_client = boto3.client('s3',
                         endpoint_url='https://s3.wasabisys.com',
                         aws_access_key_id="2YLNUKSEKM4ZJB5GVAHJ",
                         aws_secret_access_key="")
iam_client = boto3.client('iam',
                          endpoint_url='https://iam.wasabisys.com',
                          aws_access_key_id="2YLNUKSEKM4ZJB5GVAHJ",
                          aws_secret_access_key="",
                          region_name='us-east-1')

buckets = s3_client.list_buckets()
for bucket in buckets['Buckets']:
    response = s3_client.delete_bucket(Bucket=bucket['Name'])

# group_policies = iam_client.response = iam_client.list_policies(Scope='Local', OnlyAttached=True)
# for policy in group_policies['Policies']:
#     response = iam_client.detach_group_policy(GroupName=group_name, PolicyArn=policy['Arn'])

# response = iam_client.delete_group(GroupName=group_name)

users = iam_client.list_users()
for user in users['Users']:
    iam_keys = iam_client.list_access_keys(UserName=user['UserName'])

    for key in iam_keys['AccessKeyMetadata']:
        iam_client.delete_access_key(AccessKeyId=key['AccessKeyId'])
    response = iam_client.delete_user(UserName=user['UserName'])

# "sudo s3fs tryout-bucket-us-east-2-312 /abc -o passwd_file=/etc/passwd-s3fs -o url=https://s3.us-east-2.wasabisys.com"
# "umount /Users/voletiravi/Desktop/abc"
#
# "vi /etc/passwd-s3fs EOMEGDS0KJPKJ1MR9E2W:TanYtN9bpsqVIeep9usBoIzpvPMtkZZquhZnyzPH"
#
# "aws s3 mb s3://my-bucket-ap-southeast-1-122122 --endpoint-url=https://s3.ap-northeast-1.wasabisys.com"
#
# "aws s3api get-object --bucket tryout-bucket-us-east-2-312 --key abc.txt /Users/voletiravi/Desktop/b.txt --profile
# wasabi  --endpoint-url=https://s3.us-east-2.wasabisys.com"
#
# "aws s3 ls s3://tryout-bucket-us-east-2-312 --profile wasabi  --endpoint-url=https://s3.us-east-2.wasabisys.com"

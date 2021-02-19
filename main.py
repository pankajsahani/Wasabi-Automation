"""
***** This code was written by Ravi Voleti for Wasabi Technologies.inc *****
"""
import os
import sys
from typing import List
from boto3 import client, Session
import re
import json
import csv
from os import path, remove
from botocore.exceptions import ProfileNotFound, ClientError


class CreateBucketsForSelf:
    s3_client = None
    iam_client = None
    list_buckets = None
    max_buckets = 1000

    def __init__(self):
        connection_tested = False
        while not connection_tested:
            # select a profile from credentials file or enter secret key and access key.
            aws_access_key_id, aws_secret_access_key = self.get_credentials()

            region = self.region_selection()

            # create a connection to s3 with those credentials.
            connection_tested = self.create_connection_and_test(aws_access_key_id, aws_secret_access_key, region)

        # call the automation function
        self.automate()
        return

    @staticmethod
    def region_selection():
        dic = {"1": "us-east-1",
               "2": "us-east-2",
               "3": "us-central-1",
               "4": "eu-central-1",
               "5": "us-west-1"
               }
        region_selected = False
        region = ""
        while not region_selected:
            choice = input("$ Select regions by typing a corresponding number\n"
                           "$ 1: us-east-1\n"
                           "$ 2: us-east-2\n"
                           "$ 3: us-central-1\n"
                           "$ 4: eu-central-1\n"
                           "$ 5: us-west-1\n")
            if str(choice) in dic:
                region = dic[str(choice)]
                region_selected = True
        return region

    def create_connection_and_test(self, aws_access_key_id: str, aws_secret_access_key: str, region) -> bool:
        try:
            self.s3_client = client('s3',
                                    endpoint_url='https://s3.' + region + '.wasabisys.com',
                                    aws_access_key_id=aws_access_key_id,
                                    aws_secret_access_key=aws_secret_access_key)

            self.iam_client = client('iam',
                                     endpoint_url='https://iam.wasabisys.com',
                                     aws_access_key_id=aws_access_key_id,
                                     aws_secret_access_key=aws_secret_access_key,
                                     region_name='us-east-1')

            # Test credentials are working
            self.list_buckets = self.s3_client.list_buckets()
            return True

        except ClientError:
            print("Invalid Access and Secret keys")
        except Exception as e:
            raise e
        # cannot reach here
        return False

    def get_credentials(self):
        credentials_verified = False
        aws_access_key_id = None
        aws_secret_access_key = None
        while not credentials_verified:
            choice = input("$ Press 1 and enter to select existing profile\n"
                           "$ Press 2 and enter to enter Access Key and Secret Key\n"
                           "$ Press 3 to exit: ")
            if choice.strip() == "1":
                aws_access_key_id, aws_secret_access_key = self.select_profile()
                if aws_access_key_id is not None and aws_secret_access_key is not None:
                    credentials_verified = True
            elif choice.strip() == "2":
                aws_access_key_id = input("$ AWS access key").strip()
                aws_secret_access_key = input("$ AWS secret access key").strip()
                credentials_verified = True
            elif choice.strip() == "3":
                sys.exit(0)
            else:
                print("Invalid choice please try again")

        return aws_access_key_id, aws_secret_access_key

    @staticmethod
    def select_profile():
        f = False
        while not f:
            try:
                profiles = Session().available_profiles
                if len(profiles) == 0:
                    return None, None
                print("$ Available Profiles: ", profiles)
            except Exception as e:
                print(e)
                return None, None
            profile_name = input("$ Profile name: ").strip().lower()
            try:
                session = Session(profile_name=profile_name)
                credentials = session.get_credentials()
                aws_access_key_id = credentials.access_key
                aws_secret_access_key = credentials.secret_key
                f = True
                return aws_access_key_id, aws_secret_access_key
            except ProfileNotFound:
                print("$ Invalid profile. Please Try again.")
            except Exception as e:
                raise e

    @staticmethod
    def verify_name(name: str) -> bool:
        if name == "":
            print("$ name cannot be blank, retry again")
            return False
        # User names can be a combination of up to 64 letters, digits, and these characters: plus (+), equal (=),
        # comma (,), period (.), at sign (@), underscore (_), and hyphen (-).
        if len(name) > 64:
            print("name cannot be longer than 64 characters, retry again")
        if not re.fullmatch(r"[\w\d]+[\w\d+=,.@_-]*", name):
            print("$ name has invalid characters, retry again")
            return False
        return True

    @staticmethod
    def resource_path(relative_path):
        """ Get absolute path to resource, works for dev and for PyInstaller """
        return os.path.join(os.path.dirname(sys.executable), relative_path)

    def get_usernames(self) -> List[str]:
        name_choice = input("$ Press 1 to input usernames. Press 2 to select Usernames.txt file: ")
        users = []
        # input usernames
        if name_choice.strip() == "1":
            input_users = input(
                "$ enter username or usernames each separated by a space (usernames will be forced lowercase): ") \
                .strip().lower().split()

            for user in input_users:
                if self.verify_name(user):
                    users.append(user)

        # insert users through file
        if name_choice.strip() == "2":
            file_path = self.resource_path("Usernames.txt")
            if not path.exists(file_path):
                print(
                    "$ File does not exist, please create 'Usernames.txt' and add users separated by "
                    "spaces in this directory")
                sys.exit(1)
            file = open(file_path, 'r')
            for line in file:
                for user in line.strip().lower().split():
                    if self.verify_name(user):
                        users.append(user)
                    else:
                        print("$ > This username is not valid: ", user)
        return users

    def create_user(self, user: str):
        try:
            response = self.iam_client.get_user(UserName=user)
            if 200 <= response['ResponseMetadata']['HTTPStatusCode'] < 300:
                print("$ user already exists skipping.")
        except self.iam_client.exceptions.NoSuchEntityException:
            print("$ User does not exist creating one now.")
            self.iam_client.create_user(UserName=user)
        except Exception as e:
            raise e
        return

    def create_access_key(self, user: str):
        # append to file
        with open(self.resource_path('keys.csv'), 'a', newline='') as csv_file:
            file = csv.writer(csv_file)
            try:
                response = self.iam_client.list_access_keys(UserName=user)
                if len(response['AccessKeyMetadata']) > 0:
                    print(
                        "$ key exists for this user, please check for existing access "
                        "key or delete current to generate a new one. skipping")
                else:
                    print("$ creating keys for user: " + user)
                    response = self.iam_client.create_access_key(UserName=user)
                    dic = [str(response['AccessKey']['UserName']),
                           str(response['AccessKey']['AccessKeyId']),
                           str(response['AccessKey']['SecretAccessKey'])]
                    file.writerow(dic)
            except Exception as e:
                raise e

    def create_group(self, group_name):
        policy_name = "automation-policy"
        policy_file_path = self.resource_path("policy.json")

        try:
            group_response = self.iam_client.get_group(GroupName=group_name)
            if 200 <= group_response['ResponseMetadata']['HTTPStatusCode'] < 300:
                print("$ Group already exists skipping creation.")
        except self.iam_client.exceptions.NoSuchEntityException:
            print("$ Group not found creating one now.")
            try:
                group_response = self.iam_client.create_group(GroupName=group_name)
            except Exception as e:
                raise e
        except Exception as e:
            raise e

        # Skipping steps is a bad idea here as if the automation fails after creation of group then we still want to
        # create a policy and attach it to the groups.
        print("$ Creating Policy Now.")
        if not path.exists(policy_file_path):
            print("$ policy document does not exist, please create 'policy.json' in this directory")
        policy_file = open(policy_file_path)
        policy_document = json.load(policy_file)
        data = json.dumps(policy_document)
        try:
            policy_response = self.iam_client.create_policy(PolicyName=policy_name, PolicyDocument=data)
            policy_arn = policy_response['Policy']['Arn']
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                print('$ Policy already exists with that name skipping...')
                account_number = group_response["Group"]["Arn"].split(":")[4]
                policy_arn = "arn:aws:iam::" + account_number + ":policy/" + policy_name
                # try:
                #     account_number = group_response["Group"]["Arn"].split(":")[4]
                #     policy_arn = "arn:aws:iam::" + account_number + ":policy/" + policy_name
                #     policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                #     self.iam_client.create_policy_version(PolicyArn=policy_arn, PolicyDocument=data,
                #                                           SetAsDefault=True)
                # except Exception as e:
                #     raise e
            else:
                raise e
        except Exception as e:
            raise e
        try:
            print("$ Attaching policy now.")
            self.iam_client.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
        except Exception as e:
            raise e
        return

    def create_bucket(self, user: str):
        prefix = "wasabi-technologies-"
        bucket_name = prefix + user
        try:
            print("$ creating bucket named " + bucket_name)
            self.s3_client.create_bucket(Bucket=bucket_name)
        except Exception as e:
            raise e

    def add_user_to_group(self, user: str, group_name: str):
        try:
            print("$ Adding " + user + " to group " + group_name)
            self.iam_client.add_user_to_group(GroupName=group_name, UserName=user)
        except Exception as e:
            raise e

    def automate(self):
        # create users
        users = self.get_usernames()
        # sets group name for the user.
        group_name = "restricted-access-group"

        current_total_buckets = len(self.list_buckets['Buckets'])
        if len(users) + current_total_buckets >= self.max_buckets:
            print("$ WARNING " + "*" * 15)
            print("$ You currently have " + str(current_total_buckets) + " " + "buckets\n")
            print("$ By adding " + str(len(users)) + " " + "you may have " + str(
                len(users) + current_total_buckets) + " " + "buckets\n")
            choice = input("$ As there cannot be more than " + str(
                self.max_buckets) + " buckets do you want to attempt creating as many as possible? Y/n")
            if choice.strip().lower() == 'n':
                sys.exit(1)
            print("$" + "*" * 15)

        # create a file to store all access and secret keys for each user.
        p = self.resource_path('keys.csv')
        if path.exists(p):
            remove(p)
        with open(p, 'w') as csv_file:
            file = csv.writer(csv_file)
            file.writerow(['UserName', 'AccessKeyId', 'SecretAccessKey'])
            pass

        # 4. Check for Group or Create one
        print("-" * 15)
        self.create_group(group_name=group_name)

        for user in users:
            print("-" * 15)

            if current_total_buckets >= self.max_buckets:
                print("$ maximum bucket limit reached.")
                break

            # 1. create users on the Wasabi cloud
            self.create_user(user)

            # 2. create user access key on the Wasabi cloud
            self.create_access_key(user)

            # 3. create bucket with username
            self.create_bucket(user)

            # 7. attach user to group
            self.add_user_to_group(user, group_name=group_name)

            current_total_buckets = len(self.s3_client.list_buckets()['Buckets'])
        return


if __name__ == '__main__':
    print("$ Welcome To Wasabi Automation $")
    obj = CreateBucketsForSelf()
    print("-" * 15)
    print("$ Please make sure to keep the copy of the keys.csv "
          "file safe as it will be deleted at the start of next run $")
    print("-" * 15)
    print("$ Automation complete successfully $")
    print("-" * 15)
    sys.exit(0)

from typing import List

import boto3
import re
import json
from os import path
from botocore.exceptions import ProfileNotFound, ClientError


class CreateBucketsForSelf:
    s3_client = None
    iam_client = None

    def __init__(self):
        """
        1. Initializes aws key and secret key,
        2. Creates a connection to s3 and IAM
        3. Call the automation stack
        """
        f1 = False
        while not f1:
            # select a profile from credentials file or enter secret key and access key.
            aws_access_key_id, aws_secret_access_key = self.get_credentials()

            # create a connection to s3 with those credentials.
            f1 = self.create_connection_and_test(aws_access_key_id, aws_secret_access_key)

        # call the automation function
        self.automate()
        return

    def create_connection_and_test(self, aws_access_key_id: str, aws_secret_access_key: str) -> bool:
        """
        Tests the connection with list bucket and checks if given keys work.
        :param aws_access_key_id: key id.
        :param aws_secret_access_key: secret access key.
        :return:
        :return: Boolean
        """
        try:
            self.s3_client = boto3.client('s3',
                                          endpoint_url='https://s3.wasabisys.com',
                                          aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key)

            self.iam_client = boto3.client('iam',
                                           endpoint_url='https://iam.wasabisys.com',
                                           aws_access_key_id=aws_access_key_id,
                                           aws_secret_access_key=aws_secret_access_key,
                                           region_name='us-east-1')

            # Test credentials are working
            self.s3_client.list_buckets()
            return True

        except ClientError:
            print("Invalid Access and Secret keys")
        except Exception as e:
            raise e
        # cannot reach here
        return False

    def get_credentials(self):
        """
        Gets Aws key and Secret key using profile or input.
        :return: aws key id and aws secret key.
        """
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
                exit(0)
            else:
                print("Invalid choice please try again")

        return aws_access_key_id, aws_secret_access_key

    @staticmethod
    def select_profile():
        """
        Internal method for get_credentials, gets aws key and secret key from profile.
        :return: aws_access_key_id, aws_secret_access_key
        """
        f = False
        while not f:
            try:
                profiles = boto3.Session().available_profiles
                if len(profiles) == 0:
                    return None, None
                print("$ Available Profiles: ", profiles)
            except Exception as e:
                print(e)
                return None, None
            profile_name = input("$ Profile name: ").strip().lower()
            try:
                session = boto3.Session(profile_name=profile_name)
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
        """
        verifies the name according to aws complaince for naming.
        :param name: name to be tested
        :return: boolean true or false
        """
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

    def get_usernames(self) -> List[str]:
        """
        Takes input for username or a file (space separated names) that reads username line by line and creates users.
        :return: list of valid usernames
        """
        name_choice = input("$ Press 1 to input usernames. Press 2 to insert a file for usernames: ")
        users = []
        prefix_name = "wasabi-technologies-aws-"
        # input usernames
        if name_choice.strip() == "1":
            end = False
            while not end:
                user_verified = False
                user = None
                while not user_verified:
                    user = input("$ enter username (usernames will be forced lowercase): ").strip().lower()
                    # verify if username is valid
                    user_verified = self.verify_name(user)
                if prefix_name not in user:
                    user = prefix_name + user
                users.append(user)
                end_adding_users = input(
                    "$ leave blank to add more users, otherwise type "
                    "something and enter to stop adding users: ").strip()
                if end_adding_users != "":
                    end = True
        # insert users through file
        if name_choice.strip() == "2":
            f = False
            file_path = None
            while not f:
                file_path = input("$ Enter file path [file containing users each separated by a space]: ").strip()
                if path.exists(file_path):
                    f = True
                else:
                    print("$ File does not exist, please provide a valid path")
            file = open(file_path, 'r')
            for line in file:
                for user in line.strip().lower().split():
                    if not self.verify_name(user):
                        print("> This username is not valid: ", user)
                        continue
                    if prefix_name not in user:
                        user = prefix_name + user
                    users.append(user)
        return users

    def create_user(self, user: str):
        """
        sends api call to create user.
        :param user: username
        :return: nothing or error
        """
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
        """
        sends api call to create access keys and stores it in a file called keys.txt
        :param user: username
        """
        # append to file
        file = open("keys.txt", "a")
        try:
            response = self.iam_client.list_access_keys(UserName=user)
            if len(response['AccessKeyMetadata']) > 0:
                print("$ key exists skipping.")
            else:
                print("$ creating keys for user: " + user)
                response = self.iam_client.create_access_key(UserName=user)
                file.write(
                    response['AccessKey']['UserName'] + " " +
                    response['AccessKey']['AccessKeyId'] + " " +
                    response['AccessKey']['SecretAccessKey'] + "\n")
        except Exception as e:
            raise e
        file.close()

    def create_group_policy_and_attach(self, group_name):
        """
        sends api call to create group named admin. Creates a policy and attaches policy to the group.
        :param group_name:
        :return:
        """
        group_response = None
        policy_name = None
        policy_name_verified = False
        policy_found = False
        policy_file_path = None
        policy_arn = None

        try:
            group_response = self.iam_client.get_group(GroupName=group_name)
            if 200 <= group_response['ResponseMetadata']['HTTPStatusCode'] < 300:
                print("$ Group already exists skipping creation.")
        except self.iam_client.exceptions.NoSuchEntityException:
            print("$ Group not found creating one now.")
            try:
                group_response = self.iam_client.create_group_policy_and_attach(GroupName=group_name)
            except Exception as e:
                print(e)
        except Exception as e:
            raise e

        # Skipping steps is a bad idea here as if the automation fails after creation of group then we still want to
        # create a policy and attach it to the groups.
        account_number = group_response["Group"]["Arn"].split(":")[4]
        f = False
        while not f:
            while not policy_name_verified:
                policy_name = input("$ Input name of the policy: ")
                if self.verify_name(policy_name):
                    policy_name_verified = True
                else:
                    print("$ please try again.")

            try:
                policy_arn = "arn:aws:iam::" + account_number + ":policy/" + policy_name
                policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                if 200 <= policy_response['ResponseMetadata']['HTTPStatusCode'] < 300:
                    print("$ Policy already exists with that name.")
                    choice = input(
                        "$ Press 1 and enter to change name and create a policy, Press anything else and enter to skip:")
                    if choice != "1":
                        f = True
                    else:
                        policy_name_verified = False
            except self.iam_client.exceptions.NoSuchEntityException:
                f = True
                print("$ Policy not found create one now.")
                while not policy_found:
                    policy_file_path = input("$ Give the file path of the policy document: ").strip()
                    if path.exists(policy_file_path):
                        policy_found = True
                    else:
                        print("$ policy document does not exist, please recheck the path and try again.")
                policy_file = open(policy_file_path)
                policy_document = json.load(policy_file)
                data = json.dumps(policy_document)
                try:
                    policy_response = self.iam_client.create_policy(PolicyName=policy_name, PolicyDocument=data)
                    policy_arn = policy_response['Policy']['Arn']
                except Exception as e:
                    print(e)
            except Exception as e:
                raise e

        try:
            print("$ Attaching policy now.")
            self.iam_client.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
        except Exception as e:
            print(e)
        return

    def create_bucket(self, user: str):
        """
        sends api call to create bucket.
        :param user: username
        """
        try:
            print("$ creating bucket named " + user)
            self.s3_client.create_bucket(Bucket=user)
        except Exception as e:
            raise e

    def add_user_to_group(self, user: str, group_name: str):
        try:
            print("$ Adding " + user + " to group " + group_name)
            self.iam_client.add_user_to_group(GroupName=group_name, UserName=user)
        except Exception as e:
            raise e

    def automate(self):
        """
        main function.
        """
        # create users
        users = self.get_usernames()

        if len(users) > 1000:
            print("Cannot have more than 1000 users, please reduce the count.")
            exit(1)

        # create a file to store all access and secret keys for each user.
        file = open("keys.txt", "w")
        file.close()

        # 4. Check for Group or Create one
        self.create_group_policy_and_attach(group_name="admin")

        for user in users:
            print("-" * 15)
            # 1. create users on the Wasabi cloud
            self.create_user(user)

            # 2. create user access key on the Wasabi cloud
            self.create_access_key(user)

            # 3. create bucket with username
            self.create_bucket(user)

            # 7. attach user to group
            self.add_user_to_group(user, group_name="admin")


if __name__ == '__main__':
    print("$ Welcome To Wasabi Automation $")
    obj = CreateBucketsForSelf()

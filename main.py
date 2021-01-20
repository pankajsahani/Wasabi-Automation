from typing import List

import boto3
import re
from botocore.exceptions import ProfileNotFound, ClientError


class CreateBucketsForSelf:
    s3_client = None
    iam_client = None

    def __init__(self):
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
        try:
            self.s3_client = boto3.client('s3',
                                          endpoint_url='https://s3.wasabisys.com',
                                          aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key)

            self.iam_client = boto3.client('iam',
                                          endpoint_url='https://s3.wasabisys.com',
                                          aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key)

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
        f = False
        aws_access_key_id = None
        aws_secret_access_key = None
        while not f:
            choice = input("Press 1 and enter to select existing profile "
                           "Press 2 and enter to enter Access Key and Secret Key:")
            if choice.strip() == "1":
                aws_access_key_id, aws_secret_access_key = self.select_profile()
                f = True
            elif choice.strip() == "2":
                aws_access_key_id = input("AWS access key").strip()
                aws_secret_access_key = input("AWS secret access key").strip()
                f = True
            else:
                print("Invalid choice please try again")

        return aws_access_key_id, aws_secret_access_key

    @staticmethod
    def select_profile():
        f = False
        while not f:
            print("Available Profiles: ", boto3.Session().available_profiles)
            profile_name = input("Profile name: ").strip().lower()
            try:
                session = boto3.Session(profile_name=profile_name)
                credentials = session.get_credentials()
                aws_access_key_id = credentials.access_key
                aws_secret_access_key = credentials.secret_key
                f = True
                return aws_access_key_id, aws_secret_access_key
            except ProfileNotFound:
                print("Invalid profile. Please Try again.")
            except Exception as e:
                raise e

    @staticmethod
    def verify_user(user: str) -> bool:
        if user == "":
            print("username cannot be blank, retry again")
            return False
        # User names can be a combination of up to 64 letters, digits, and these characters: plus (+), equal (=),
        # comma (,), period (.), at sign (@), underscore (_), and hyphen (-).
        if len(user) > 64:
            print("username cannot be longer than 64 characters, retry again")
        if not re.fullmatch(r"[\w\d]+[\w\d+=,.@_-]*", user):
            print("username has invalid characters, retry again")
            return False
        return True

    def get_usernames(self):
        name_choice = input("Press 1 to input usernames. Press 2 to insert a file for usernames")
        users = []
        # input usernames
        if name_choice.strip() == "1":
            end = False
            while not end:
                user_verified = False
                user = None
                while not user_verified:
                    user = input("enter username (usernames will be forced lowercase): ").strip().lower()
                    # verify if username is valid
                    user_verified = self.verify_user(user)
                if "wasabi-technologies-$aws:" not in user:
                    user = "wasabi-technologies-$aws:" + user
                users.append(user)
                end_adding_users = input(
                    "leave blank to add more users,otherwise type something and enter to stop adding users").strip()
                if end_adding_users != "":
                    end = True
        # insert users through file
        if name_choice.strip() == "2":
            file_path = input("Enter file path containing users each separated by a (space) ").strip()
            file = open(file_path, 'r')
            for line in file:
                for user in line.strip().lower().split():
                    if not self.verify_user(user):
                        print("This username is not valid: ", user)
                        continue
                    if "wasabi-technologies-$aws:" not in user:
                        user = "wasabi-technologies-$aws:" + user
                    users.append(user)
        return users

    def generate_users(self, users: List[str]):
        for user in users:
            print(user)

    def automate(self):
        # create users
        users = self.get_usernames()

        # send via cli and generate users on the Wasabi cloud
        self.generate_users(users)


if __name__ == '__main__':
    print("Welcome To Wasabi Automation")
    obj = CreateBucketsForSelf()

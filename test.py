import re

a = re.fullmatch(r"[\w\d]+[\w\d+=,.@_-]*", "s@!#@")
print(a)
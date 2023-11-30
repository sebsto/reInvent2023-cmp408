## Title : Automating and Managing Amazon EC2 Mac instances at-scale

**Abstract** This session will be diving deep into how Amazon EC2 Mac instances are launched, configured, and kept up to date. We'll be creating scripts to spin up instances, discovering utilities that can keep apps up to date, checking out Systems Manager to run commands, take a look at in-place and beta updates, and integrate with Jamf for mobile device management.

## Code Talk 

### 1. Quick recap / intro about Amazon EC2 Mac

**Slide** : #3 (image of a Mac Mini in a rack)

**Talking Points**:

- Mac Mini in the cloud. x86, M1, M2 Pro
- dedicated host 
- pricing on dedicated host with min 24h 
- scrubbing process 
- EBS, Snapshots and AMI
- show command line to reserve a dedicated host 

```bash
# reserve a dedicated host

aws ec2 allocate-hosts                   \ 
     --instance-type mac2.metal          \ 
     --availability-zone us-east-2b      \ 
     --quantity 1 

# Response
{
    "HostIds": [
        "h-0fxxxxxxx90"
    ]
}
```
- show command line to start an EC2 Mac 

```bash
# start an instance

 aws ec2 run-instances                                         \ 
        --instance-type mac2.metal                             \ 
        --key-name my_key                                      \ 
        --placement HostId=h-0fxxxxxxx90                       \ 
        --security-group-ids sg-01000000000000032              \ 
        --image-id AWS_OR_YOUR_AMI_ID

# Response
{
    "Groups": [],
    "Instances": [
        {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-01xxxxbd",
            "InstanceId": "i-08xxxxx5c",
            "InstanceType": "mac2.metal",
            "KeyName": "my_key",
            "LaunchTime": "2021-11-08T16:47:39+00:00",
            "Monitoring": {
                "State": "disabled"
            },
... redacted for brevity ....

```

### 2. EC2 User Data to customize macOS at boot time 

**Slide** : None

**Talking Points**:

- recap what user data is and how it works 
- show macos init process 
- show an example of user data script 
- show how to reset the macos init execution flag

#### macOS init

Available from [https://github.com/aws/ec2-macos-init](https://github.com/aws/ec2-macos-init)

Configuration files

```sh
% cat /usr/local/aws/ec2-macos-init/init.toml
### Group 1 ###
## Making sure unnecessary resources are disabled

# Disable Ethernet
[[Module]]
    Name = "DisableEthernet"
    PriorityGroup = 1 # First group
    RunPerBoot = true # Run every boot
    FatalOnError = true # Fatal if there's an error - this must succeed
    [Module.Command]
        Cmd = ["/usr/sbin/networksetup", "-setnetworkserviceenabled", "Ethernet", "off"]
...
[[Module]]
    Name = "ExecuteUserData"
    PriorityGroup = 5 # Fifth group
    RunPerInstance = true # Run once per instance
    FatalOnError = false # Best effort, don't fatal on error
    [Module.UserData]
        ExecuteUserData = true # Execute the userdata
```

Accessing the logs 

```
% cat /var/log/amazon/ec2/ec2-macos-init.log

...
2023/10/30 18:42:19.575916 Successfully completed module [UnmountLocalSSD]
...
2023/10/30 18:42:19.587436 Running module [SetAmazonTimeSync]
...
2023/10/30 18:42:19.587477 Running module [DisableWiFi] 
...
2023/10/30 18:42:19.587463 Running module [NeverSleep]
2023/10/30 18:42:40.771346 Successfully completed module [GetSSHKeys] with message: successfully added 1 keys to authorized_users
...
2023/10/30 18:42:40.771392 Running module [ExecuteUserData]
```

User data: 
- any text data (your application can read them from IMDS)
- base64 encoded
- when starts with `#!`, considered as a script and run as `root` user

Example:

```sh
% cat bootstrap.sh 

#!/bin/sh

CURRENT_USER=$(whoami)
echo "Hello from shell script as user: \"$CURRENT_USER\""
```

Pass user data script when starting the instance

```bash
 % aws ec2 run-instances                                       \ 
        --instance-type mac2.metal                             \ 
        --key-name my_key                                      \ 
        --placement HostId=h-0fxxxxxxx90                       \ 
        --security-group-ids sg-01000000000000032              \ 
        --image-id AWS_OR_YOUR_AMI_ID                          \
		--user-data file://bootstrap.sh
```

Access user data from IMDS
```sh
% TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
% curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data/

#!/bin/sh

CURRENT_USER=$(whoami)
echo "Hello from shell script as user: \"$CURRENT_USER\""
```		

#### Debugging 

The downloaded script is available at

```sh
% cat /usr/local/aws/ec2-macos-init/instances/i-06946175391dd147e/userdata

#!/bin/sh

CURRENT_USER=$(whoami)
echo "Hello from shell script as user: \"$CURRENT_USER\""%  
```

Terminate and re-start cycles are long because of scrubbing. Previous execution files are kept in `/usr/local/aws/ec2-macos-init/instances`

```sh
% ls -al /usr/local/aws/ec2-macos-init/instances/i-012a5de8da47bdff7/
total 8
drwxr-xr-x  3 root  wheel    96 Nov 23 17:03 .
drwxr-xr-x  3 root  wheel    96 Nov 23 17:03 ..
-rw-------  1 root  wheel  1198 Nov 23 17:03 history.json

% sudo ec2-macos-init clean
% sudo ec2-macos-init run
```

#### Best practice

Externalize your user data script.  Download, modify, run.

Here is an example of a generic user data script that downloads the actual payload from the web and runs it. You have to trust the source of the script (think about signature, private VPC endpoint etc.)

```sh
#!/bin/sh 
REMOTE_SCRIPT_URL=https://gist.githubusercontent.com/sebsto/6b2f976d7bd6e84dd2eb147c0a7af9f8/raw/71cb67d980e2b03aac9b99f203f42010cb62fa0d/Test%2520User%2520Data
LOCAL_FILENAME=/tmp/shell_script.sh
NON_PRIVILEDGED_USER=ec2-user

curl -s -o $LOCAL_FILENAME "$REMOTE_SCRIPT_URL"
chmod u+x $LOCAL_FILENAME
chown $NON_PRIVILEDGED_USER:staff $LOCAL_FILENAME
su -m $NON_PRIVILEDGED_USER $LOCAL_FILENAME > /tmp/out # beware of env variables accessible or not from the target script (read `man su` for a detailed discussion)
rm $LOCAL_FILENAME
```

The execution log

```
Successfully completed module [ExecuteUserData] (type: userdata, group: 5) with message: successfully ran user data with stdout: [Hello from shell script as user: "root"] and stderr: []
```

### 3. AWS Systems Manager (SSM) to customize macOS at boot time 

**Slide** : None

**Talking Points**:
 
- recap what SSM is and how it works 
- show SSM macOS agent 
- show an example of executing command with SSM 

#### Is the agent started?

```sh 
% ps ax | grep -i ssm | grep aws
  377   ??  Ss    15:53.61 /opt/aws/ssm/bin/amazon-ssm-agent
  449   ??  S     28:03.41 /opt/aws/ssm/bin/ssm-agent-worker
```

#### Does my instance has permission to communicate with the SSM service ?

```sh
% aws ec2 describe-instances --instance-ids i-012a5de8da47bdff7  \
  						     --query 'Reservations[*].Instances[*].IamInstanceProfile.Arn' \
						     --output text | sed  "s/.*\///"

macOS_CICD_Amplify_profile
```

```sh
% aws iam list-attached-role-policies --role-name macOS_CICD_Amplify
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonSSMManagedInstanceCore",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
        }
    ]
}
```

#### Send a command 

```sh
% aws ssm send-command --document-name AWS-RunShellScript     \
                     --comment "demo running shell script"    \
                     --instance-ids i-012a5de8da47bdff7       \
                     --parameters "commands=id && pwd && ls -al" 
```

#### Read the command output 

```sh
% aws ssm get-command-invocation --instance-id i-012a5de8da47bdff7 \
                               --command-id 52c0801e-8514-4edf-87b6-38b49685417c
{
    "CommandId": "52c0801e-8514-4edf-87b6-38b49685417c",
    "InstanceId": "i-012a5de8da47bdff7",
    "Comment": "demo running shell script",
    "DocumentName": "AWS-RunShellScript",
    "DocumentVersion": "$DEFAULT",
    "PluginName": "aws:runShellScript",
    "ResponseCode": 0,
    "ExecutionStartDateTime": "2023-11-23T18:54:59.596Z",
    "ExecutionElapsedTime": "PT0.06S",
    "ExecutionEndDateTime": "2023-11-23T18:54:59.596Z",
    "Status": "Success",
    "StatusDetails": "Success",
    "StandardOutputContent": "uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),400(com.apple.access_remote_ae)\n/\ntotal 11\ndrwxr-xr-x  20 root  wheel   640 Feb  9  2023 .\ndrwxr-xr-x  20 root  wheel   640 Feb  9  2023 ..\nlrwxr-xr-x   1 root  admin    36 Feb  9  2023 .VolumeIcon.icns -> System/Volumes/Data/.VolumeIcon.icns\n----------   1 root  admin     0 Feb  9  2023 .file\ndrwxr-xr-x   2 root  wheel    64 Feb  9  2023 .vol\ndrwxrwxr-x  12 root  admin   384 Oct 12 15:18 Applications\ndrwxr-xr-x  65 root  wheel  2080 Apr  2  2023 Library\ndrwxr-xr-x@ 10 root  wheel   320 Feb  9  2023 System\ndrwxr-xr-x   6 root  admin   192 Mar 26  2023 Users\ndrwxr-xr-x   3 root  wheel    96 Nov 15 07:54 Volumes\ndrwxr-xr-x@ 39 root  wheel  1248 Feb  9  2023 bin\ndrwxr-xr-x   2 root  wheel    64 Dec  2  2022 cores\ndr-xr-xr-x   4 root  wheel  5436 Nov 15 07:54 dev\nlrwxr-xr-x@  1 root  wheel    11 Feb  9  2023 etc -> private/etc\nlrwxr-xr-x   1 root  wheel    25 Nov 15 07:54 home -> /System/Volumes/Data/home\ndrwxr-xr-x   5 root  wheel   160 Feb 14  2023 opt\ndrwxr-xr-x   6 root  wheel   192 Nov 15 07:54 private\ndrwxr-xr-x@ 64 root  wheel  2048 Feb  9  2023 sbin\nlrwxr-xr-x@  1 root  wheel    11 Feb  9  2023 tmp -> private/tmp\ndrwxr-xr-x@ 11 root  wheel   352 Feb  9  2023 usr\nlrwxr-xr-x@  1 root  wheel    11 Feb  9  2023 var -> private/var\n",
    "StandardOutputUrl": "",
    "StandardErrorContent": "",
    "StandardErrorUrl": "",
    "CloudWatchOutputConfig": {
        "CloudWatchLogGroupName": "",
        "CloudWatchOutputEnabled": false
    }
}
```

Not really clear? Let's filter out.

```sh
% aws ssm get-command-invocation --region us-east-1 \
                                 --instance-id i-012a5de8da47bdff7 \
							     --command-id 52c0801e-8514-4edf-87b6-38b49685417c \
							     --query StandardOutputContent | sed "s/\\\n/\n/g" 

"uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),400(com.apple.access_remote_ae)
/
total 11
drwxr-xr-x  20 root  wheel   640 Feb  9  2023 .
drwxr-xr-x  20 root  wheel   640 Feb  9  2023 ..
lrwxr-xr-x   1 root  admin    36 Feb  9  2023 .VolumeIcon.icns -> System/Volumes/Data/.VolumeIcon.icns
----------   1 root  admin     0 Feb  9  2023 .file
drwxr-xr-x   2 root  wheel    64 Feb  9  2023 .vol
drwxrwxr-x  12 root  admin   384 Oct 12 15:18 Applications
drwxr-xr-x  65 root  wheel  2080 Apr  2  2023 Library
drwxr-xr-x@ 10 root  wheel   320 Feb  9  2023 System
drwxr-xr-x   6 root  admin   192 Mar 26  2023 Users
drwxr-xr-x   3 root  wheel    96 Nov 15 07:54 Volumes
drwxr-xr-x@ 39 root  wheel  1248 Feb  9  2023 bin
drwxr-xr-x   2 root  wheel    64 Dec  2  2022 cores
dr-xr-xr-x   4 root  wheel  5436 Nov 15 07:54 dev
lrwxr-xr-x@  1 root  wheel    11 Feb  9  2023 etc -> private/etc
lrwxr-xr-x   1 root  wheel    25 Nov 15 07:54 home -> /System/Volumes/Data/home
drwxr-xr-x   5 root  wheel   160 Feb 14  2023 opt
drwxr-xr-x   6 root  wheel   192 Nov 15 07:54 private
drwxr-xr-x@ 64 root  wheel  2048 Feb  9  2023 sbin
lrwxr-xr-x@  1 root  wheel    11 Feb  9  2023 tmp -> private/tmp
drwxr-xr-x@ 11 root  wheel   352 Feb  9  2023 usr
lrwxr-xr-x@  1 root  wheel    11 Feb  9  2023 var -> private/var
```

### 4. Put it all together 

**Slide** : None

**Talking Points**:
 
- recap of what Cloudformation is 
- show an example of CFN template to allocate a dedicated host, start an instance with user data

```yaml
AWSTemplateFormatVersion: 2010-09-09

Resources:

  SGfor22and5900:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow ssh and vnc-windows
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 5900
          ToPort: 5900
          CidrIp: 0.0.0.0/0
      VpcId: 
        Fn::ImportValue: WorkshopVPC

  machost:
    Type: AWS::EC2::Host
    Properties:
      AvailabilityZone: us-east-2c
      InstanceType: mac2.metal
      AutoPlacement: 'on'

  M1instance:
    Type: AWS::EC2::Instance
    DependsOn: 
    - machost
    - SGfor22and5900
    Properties:
      BlockDeviceMappings:
        - DeviceName: /dev/sda1
          Ebs:
            VolumeType: gp3
            Iops: 4000
      ImageId: AWS_OR_YOUR_AMI_ID
      InstanceType: mac2.metal
      Tenancy: host
      IamInstanceProfile: Ec2RoleForSSM
      SecurityGroupIds:
      - !GetAtt SGfor22and5900.GroupId
      Tags:
      - Key: Name
        Value: "macos_on_aws"
      - Key: ssm
        Value: "provisioner"
      UserData:
        Fn::Base64:
          !Sub |
			#!/bin/sh

			CURRENT_USER=$(whoami)
			echo "Hello from shell script as user: \"$CURRENT_USER\""
```

### 5. Connecting to the GUI
- When not to (most of the time)
- Why:
    - MDM enrollment
	- Software updates
	- Troubleshooting
	- UI automation
	- Guided issue recreation
	- Login-triggered events

- Sample User Data script with GUI activation and user password set included in setup for enrollment.

Methods of connecting to macOS GUI
- VNC
	- Compatible
	- Slow
	- Inaccurate Color
	- Limited Options

- Screen Sharing
	- macOS Only
	- Similar to VNC
	- File/clipboard sharing
	- Apple Remote Desktop for more advanced administration
	- High Performance (newest Macs only)

- HP Anyware
	- Formerly Teradici CAS
	- PC over IP standard
	- Compressed audio & video
	- Encrypted connection
	- Others with similar abilities include Parsec, TeamViewer, and LogMeIn

### 5. Automatic enrolment to Jamf 

**Slide** : None

**Talking Points**:

- AMI setup script
```sh
#!/bin/sh

PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/opt/homebrew/sbin"

# Account name to use for enrollment.
autoLoginAccount="_ec2-mdm-enroll"

# AWS Secrets Manager secrets containing password for the above account. As written, this is a single entry (password).
credentialID="sample-secret-id-or-arn"

### Metadata token for authorization to retrieve data from local EC2 Mac instance,
MDToken=$(curl -X PUT "http://169.254.169.254/latest/api/token" -s -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
### Takes the current instance ID from the instance's metadata.
currentRegion=$(curl -H "X-aws-ec2-metadata-token: $MDToken" -s http://169.254.169.254/latest/meta-data/placement/region)

### Override here if Secrets Manager secret is in another region.
# currentRegion="us-east-1"
# su -l "$autoLoginAccount" -c  "defaults write /Users/$autoLoginAccount/Library/Preferences/com.amazon.dsx.ec2.enrollment.automation secretRegion $currentRegion" && echo "Region overridden for enrollment credentials."

# Retrieves password from AWS Secrets Manager.
EBSAdminPassword=$(aws secretsmanager get-secret-value --region $currentRegion --secret-id "$credentialID" --query SecretString --output text)

function createUserAccount () (
	userToCreate="${1}"
	userPassword="${2}"
	userID="${3}"
	# sudo /usr/bin/dscl . -create "/Users/$userToCreate" IsHidden 1 UserShell /bin/zsh UniqueID "$userID" PrimaryGroupID 1000 NFSHomeDirectory "/Users/.$userToCreate"
	# sudo /usr/bin/dscl . -passwd "/Users/$userToCreate" "$userPassword"
    sudo /usr/sbin/sysadminctl -addUser "$userToCreate" -fullName "$userToCreate" -UID "$userID" -GID 80 -shell /bin/zsh -password "$userPassword" -home "/Users/$userToCreate"
    sudo /usr/sbin/createhomedir -c -u "$userToCreate"
)

function kcpasswordEncode () (
#Licensed under the MIT License
#kcpasswordEncode (20220610) Copyright (c) 2021 Joel Bruner (https://github.com/brunerd)
	thisString="${1}"
	cipherHex_array=( 7D 89 52 23 D2 BC DD EA A3 B9 1F )
	thisStringHex_array=( $(/bin/echo -n "${thisString}" | xxd -p -u | sed 's/../& /g') )
	if [ "${#thisStringHex_array[@]}" -lt 12  ]; then
		padding=$(( 12 -  ${#thisStringHex_array[@]} ))
	elif [ "$(( ${#thisStringHex_array[@]} % 12 ))" -ne 0  ]; then
		padding=$(( (12 - ${#thisStringHex_array[@]} % 12) ))
	else
		padding=12
	fi	
	for ((i=0; i < $(( ${#thisStringHex_array[@]} + ${padding})); i++)); do
		charHex_cipher=${cipherHex_array[$(( $i % 11 ))]}

		charHex=${thisStringHex_array[$i]}
		printf "%02X" "$(( 0x${charHex_cipher} ^ 0x${charHex:-00} ))" | xxd -r -p > /dev/stdout
	done
)

# Creates and elevates autoLoginAccount to admin.
autoLoginUID="1002"
createUserAccount "$autoLoginAccount" "$EBSAdminPassword" $autoLoginUID
sudo /usr/bin/dscl . -append /Groups/admin GroupMembership "$autoLoginAccount"

# Activates Screen Sharing/VNC. Required to connect to the instance's GUI.
sudo launchctl enable system/com.apple.screensharing ; sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.screensharing.plist

# Setup for enroll-ec2-mac script and staging area for auto-login database,
stagingDir="/Users/Shared/._enroll-ec2-mac"

sudo mkdir -p "$stagingDir"
sudo chown "$autoLoginAccount:staff" "$stagingDir"

# Downloads enroll-ec2-mac script from GitHub.
sudo curl -H 'Accept: application/vnd.github.v3.raw' https://api.github.com/repos/aws-samples/amazon-ec2-mac-mdm-enrollment-automation/contents/enroll-ec2-mac.scpt | sudo tee "/Users/Shared/enroll-ec2-mac.scpt" > /dev/null
sudo chmod +x "/Users/Shared/enroll-ec2-mac.scpt"
sudo chown "$autoLoginAccount:staff" "/Users/Shared/enroll-ec2-mac.scpt"

# Installs cliclick as ec2-user, used by enroll-ec2-mac. 
su -l "ec2-user" -c "PATH=$PATH ; export HOMEBREW_NO_AUTO_UPDATE=1 ; brew install cliclick"
sleep 1
copyClickPath=$(su -l "ec2-user" -c "PATH=$PATH; which cliclick")
sudo cp -L "$copyClickPath" "$stagingDir"
sudo chown "$autoLoginAccount:staff" "$stagingDir/cliclick"
sudo chmod +x "$stagingDir/cliclick"

# Operations to enable auto-login.

sudo defaults write "/Library/Preferences/com.apple.loginwindow" autoLoginUser "$autoLoginAccount"
sudo sysadminctl -autologin set -userName "$autoLoginAccount" -password "$EBSAdminPassword"

sudo chmod -R 775 "$stagingDir"

kcpasswordEncode "$EBSAdminPassword" > "$stagingDir/kcpassword"
sudo cp "$stagingDir/kcpassword" "/etc/"

sudo chown root:wheel "/etc/kcpassword"
sudo chmod u=rw,go= "/etc/kcpassword"

EnrollLaunchAgent='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <false/>
        <key>Label</key>
        <string>com.amazon.dsx.ec2.enrollment.automation.startup</string>
        <key>LimitLoadToSessionType</key>
        <string>Aqua</string>
        <key>ProgramArguments</key>
        <array>
                <string>/usr/bin/osascript</string>
                <string>/Users/Shared/enroll-ec2-mac.scpt</string>
                <string>--firstrun</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>/tmp/MMErrors.log</string>
        <key>StandardOutPath</key>
        <string>/tmp/MMOutput.log</string>
</dict>
</plist>'

echo "$EnrollLaunchAgent" | sudo tee /tmp/com.amazon.dsx.ec2.enrollment.automation.startup.plist
sudo cp "/tmp/com.amazon.dsx.ec2.enrollment.automation.startup.plist" "/Library/LaunchAgents/"

# Eliminates Setup Assistant steps during initial login.
sudo cp -R "/Users/ec2-user/Library/Preferences/com.apple.SetupAssistant.plist" "/Users/$autoLoginAccount/Library/Preferences/" && echo "Success"
sudo chown '$autoLoginAccount:staff' "/Users/$autoLoginAccount/Library/Preferences/com.apple.SetupAssistant.plist" && echo "Success"
su -l "$autoLoginAccount" -c "chown '$autoLoginAccount:staff' /Users/$autoLoginAccount/Library/Preferences/com.apple.SetupAssistant.plist" && echo "Success"
su -l "$autoLoginAccount" -c  "defaults write /Users/$autoLoginAccount/Library/Preferences/com.apple.SetupAssistant DidSeeTermsOfAddress 1" && echo "Success"
su -l "$autoLoginAccount" -c  "defaults write /Users/$autoLoginAccount/Library/Preferences/com.apple.SetupAssistant DidSeeAccessibility 1" && echo "Success"

sudo launchctl asuser $autoLoginUID launchctl load -w /Library/LaunchAgents/com.amazon.dsx.ec2.enrollment.automation.startup.plist && echo "LaunchAgent Loaded" || echo "LaunchAgent failed to auto-load."

# When complete, (partially) reboot once into the new auto-login user.
sleep 5

if [ -f "$stagingDir/.userSetupComplete" ]; then
    sleep 1
else
    touch "$stagingDir/.userSetupComplete"
    sudo launchctl reboot userspace
fi

# Once this script is complete, connect to the GUI and log in as $autoLoginAccount.
# 
# After connecting, a few prompts will appear that must be accepted.
# Once those are complete, click OK (first) and you're free to create your image.
```
- Create AMI

- Connect via VNC/Screen Sharing
```
ssh -L 5900:localhost:5900 -i '/path/to/key.pem' 'ec2-user@ec2-256-128-64-32.compute-X.amazonaws.com'

# or 

aws ssm start-session --target $INSTANCE_ID \
                       --document-name AWS-StartPortForwardingSession \
                       --parameters '{"portNumber":["5900"],"localPortNumber":["5900"]}'

open vnc://localhost
```

### 6. Software Updates 

**Slide** : None

**Talking Points**:
 
- Introduce feature
- Difference between mac1 and mac2
- Concept of disk ownership in macOS
- Automating mac2 update activation with BoosterRocket:

```sh
#!/bin/sh

# BoosterRocket!
# Enable in-place software updates for Amazon Web Services EC2 Mac2 instances.
# Once this script has run, log in to the GUI, reboot, and wait about a minute before re-connecting as aws-managed-user.

# *** This operation won't be successful unless a user has logged into the macOS GUI. ***

# If, after a reboot, it locks in a loop asking for credentials,
# it's a good sign that a user hasn't been logged in on the GUI-side yet.

# Important: set to the ID of your matching AWS Secrets Manager secret or SSM Parameter Store parameter.
# Example templates are available for secret and IAM requirements.

credentialID="SAMPLE"

PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/opt/homebrew/sbin"

MDToken=$(curl -X PUT "http://169.254.169.254/latest/api/token" -s -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
### Takes the current instance ID from the instance's metadata.
currentRegion=$(curl -H "X-aws-ec2-metadata-token: $MDToken" -s http://169.254.169.254/latest/meta-data/placement/region)

# Replace these with credentials for your EC2 Mac admin user. The default username is "ec2-user".
EBSAdminUser="ec2-user"

EBSAdminPassword=$(aws secretsmanager get-secret-value --region $currentRegion --secret-id "$credentialID" --query SecretString --output text)

# Uncomment the line below to set the password above if there's not one yet on your EC2 instance yet. 

sudo /usr/bin/dscl . -passwd /Users/$EBSAdminUser "$EBSAdminPassword"
sudo launchctl enable system/com.apple.screensharing ; sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.screensharing.plist

# Uncommenting above will set the password to EC2AdminPassword defined further up and enable screen sharing.
#kcpasswordEncode (20220610) Copyright (c) 2021 Joel Bruner (https://github.com/brunerd)
function kcpasswordEncode () (

	thisString="${1}"

	cipherHex_array=( 7D 89 52 23 D2 BC DD EA A3 B9 1F )

	thisStringHex_array=( $(/bin/echo -n "${thisString}" | xxd -p -u | sed 's/../& /g') )

	if [ "${#thisStringHex_array[@]}" -lt 12  ]; then
		padding=$(( 12 -  ${#thisStringHex_array[@]} ))
	elif [ "$(( ${#thisStringHex_array[@]} % 12 ))" -ne 0  ]; then
		padding=$(( (12 - ${#thisStringHex_array[@]} % 12) ))
	else
		padding=12
	fi	

	for ((i=0; i < $(( ${#thisStringHex_array[@]} + ${padding})); i++)); do
		charHex_cipher=${cipherHex_array[$(( $i % 11 ))]}
		charHex=${thisStringHex_array[$i]}
		printf "%02X" "$(( 0x${charHex_cipher} ^ 0x${charHex:-00} ))" | xxd -r -p > /dev/stdout
	done
)

# If BoosterRocket has run, don't do anything! Useful for a launching with a User Data script.
if [ ! -f "/Users/Shared/.BoosterRocket.splashdown" ]; then

# The name of the current EBS volume.
EBSVolumeName=$(diskutil info -plist "$(bless --getBoot)" |  plutil -extract VolumeName raw -- -)
echo "Current boot volume detected as $EBSVolumeName."

# The internal SSD is named InternalDisk by default. If your instance is different, it may require an update.
targetMountName="InternalDisk"
internalMount=$(diskutil list | grep 'Physical Store disk0' -B 3 -A 5)
internalOSMount=$(echo "$internalMount"  | grep "$targetMountName" | awk '{print $NF}')
internalDataMount=$(echo "$internalMount"  | grep "Data" | awk '{print $NF}')

diskutil mount "$internalOSMount"
diskutil mount "$internalDataMount"

sudo bless --mount "/Volumes/$targetMountName" --setBoot --stdinpass <<< cat "$EBSAdminPassword"

# Two files go to the InternalDisk, the LaunchAgent runs the script at startup: 

BoosterRocketLaunchAgent='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <true/>
        <key>Label</key>
        <string>com.amazon.dsx.boosterrocket</string>
        <key>ProgramArguments</key>
        <array>
                <string>/usr/bin/osascript</string>
                <string>/Users/Shared/.BoosterRocket/.BoosterRocket.scpt</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
</dict>
</plist>'

BoosterRocketLoginLaunch='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <true/>
        <key>Label</key>
        <string>com.amazon.dsx.boosterrocket.login.reboot</string>
        <key>P/sbin/rogramArguments</key>
        <array>
                <string>/sbin/reboot</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
</dict>
</plist>'

BoosterRocketLaunchDaemon='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <false/>
        <key>Label</key>
        <string>com.amazon.dsx.boosterrocket.credentials</string>
        <key>ProgramArguments</key>
        <array>
                <string>/bin/sh</string>
                <string>/Users/Shared/.BoosterRocket/.BoosterRocket.sh</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>/tmp/com.amazon.dsx.boosterrocket.err</string>
        <key>StandardOutPath</key>
        <string>/tmp/com.amazon.dsx.boosterrocket.out</string>
</dict>
</plist>'

mkdir -p "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/"
sudo chown -R 501:20 "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/"


cat << EOS > "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/.BoosterRocket.sh"
#!/bin/sh

if [ ! -f /Users/Shared/.BoosterRocket/.userSet ]; then
printf "\n" | sudo /usr/bin/dscl . -passwd /Users/aws-managed-user "$EBSAdminPassword"
sudo launchctl enable system/com.apple.screensharing ; sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.screensharing.plist
sudo sysadminctl -autologin set -userName "aws-managed-user" -password "$EBSAdminPassword"
touch /Users/Shared/.BoosterRocket/.userSet
sudo reboot
else
sudo rm -f /Users/Shared/.BoosterRocket/.BoosterRocket.sh
sudo rm -f /Library/LaunchDaemons/com.amazon.dsx.boosterrocket.credentials.plist || true
sudo launchctl unload -w /Library/LaunchDaemons/com.amazon.dsx.boosterrocket.credentials.plist || true
fi

EOS


cat << EOF > "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/.BoosterRocket.scpt"
--BoosterStage
--Tested with macOS 13.2.1 on Apple silicon!

set targetVolume to "$EBSVolumeName"
set managedUserPassword to "$EBSAdminPassword"
set authorizedVolumeUser to "$EBSAdminUser"
set authorizedVolumePassword to "$EBSAdminPassword"


on securityCheckVentura(cycleCount)
	tell application "System Events" to tell process "SecurityAgent"
		repeat cycleCount times
			try
				set securityOverlay to get value of static text 1 of window 1
			on error
				set securityOverlay to ""
			end try
			if securityOverlay contains "Startup Disk" then
				delay 0.2
				exit repeat
			else
				delay 0.1
			end if
		end repeat
	end tell
end securityCheckVentura

on clickHere(clickUIElement, appName)
	tell application "System Events" to tell process appName
		tell clickUIElement
			set {xPosition, yPosition} to position
			set {xSize, ySize} to size
		end tell
		do shell script "/Users/Shared/.BoosterRocket/cliclick dc:" & (xPosition + (xSize div 2)) & "," & (yPosition + (ySize div 2))
	end tell
end clickHere

on pasteAndClear(pasteContent)
	tell application "System Events"
		set the clipboard to pasteContent
		delay 0.1
		keystroke "v" using command down
		delay 0.1
		set the clipboard to null
	end tell
end pasteAndClear

on dsUIScriptEnable()
	set self to name of current application
	set OSVersion to system version of (system info)
	tell application "System Events"
		set UIEnabledStatus to (get UI elements enabled)
	end tell
	if UIEnabledStatus is not true then
		if OSVersion starts with "13" then
			set activeSettingsApp to "System Settings"
			display dialog "This script requires Accessibility permissions to function. After clicking OK on this message, please click Accessibility on the right side (you may need to scroll down), and click the switch next to " & self & " on the right."
			do shell script "open /System/Library/PreferencePanes/Security.prefPane"
		else
			set activeSettingsApp to "System Preferences"
			display dialog "This script requires Accessibility permissions to function. After clicking OK on this message, please enter your password, click Accessibility on the left, and click the check box next to " & self & " on the right."
			do shell script "osascript -e 'tell application \"System Preferences\" to activate'"
			do shell script "osascript -e 'tell application \"System Preferences\" to reveal anchor \"Privacy\" of pane id \"com.apple.preference.security\""
			do shell script "osascript -e 'tell application \"System Preferences\" to authorize pane id \"com.apple.preference.security\""
		end if
		repeat until UIEnabledStatus is true
			tell application "System Events"
				set UIEnabledStatus to (get UI elements enabled)
			end tell
			delay 0.5
		end repeat
		display notification "Thank you! " & self & " will now run."
	end if
end dsUIScriptEnable
--Preserve the clipboard, if any.
try
set clipSave to the clipboard
end try
set the clipboard to authorizedVolumePassword
my dsUIScriptEnable()
try
set the clipboard to clipSave
on error
set the clipboard to null
end try

try
do shell script "rm -d '/Users/aws-managed-user/Desktop/Prompting for permission…'"
end try

try
	tell application "System Settings" to quit
	delay 1
end try

do shell script "open /System/Library/PreferencePanes/StartupDisk.prefPane"
delay 3

tell application "System Events" to tell process "System Settings"
	repeat with i from 1 to 4
		set targetStartup to (get value of static text 1 of group i of list 1 of scroll area 1 of group 1 of scroll area 1 of group 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1)
		if targetStartup is targetVolume then
			my clickHere(group i of list 1 of scroll area 1 of group 1 of scroll area 1 of group 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1, "System Settings")
			exit repeat
		end if
	end repeat
	delay 0.5
	click button "Restart…" of group 1 of scroll area 1 of group 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1
end tell

tell application "System Events" to tell process "SecurityAgent"
	delay 3
	my pasteAndClear(managedUserPassword)
	keystroke return
end tell
tell application "System Events" to tell process "System Settings"
	delay 3
	click button "Restart" of sheet 1 of window 1
	delay 2
	click button "Authorize Users…" of sheet 1 of window "Startup Disk"
    delay 2
	repeat with userListID from 1 to 10
		try
			set userTarget to (get value of static text 1 of UI element 1 of row userListID of table 1 of scroll area 1 of sheet 1 of window 1)
			if userTarget contains authorizedVolumeUser then
				click button "Authorize…" of UI element 1 of row 1 of table 1 of scroll area 1 of sheet 1 of window "Startup Disk"
				exit repeat
			end if
		end try
	end repeat
	delay 1
	my pasteAndClear(authorizedVolumePassword)
	keystroke return
	delay 2
	click button "Continue" of sheet 1 of window "Startup Disk"
	delay 2
	my pasteAndClear(managedUserPassword)
	keystroke return
    delay 10
end tell


EOF

kcpasswordEncode "$EBSAdminPassword" > "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/kcpassword"

# Writing auto-login to both for a reboot test.
sudo cp "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/kcpassword" "/etc/"
sudo mv "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/kcpassword" "/Volumes/$targetMountName/etc/"

sudo chown root:wheel "/Volumes/$targetMountName/etc/kcpassword"
sudo chmod u=rw,go= "/Volumes/$targetMountName/etc/kcpassword"

sudo chown root:wheel "/etc/kcpassword"
sudo chmod u=rw,go= "/etc/kcpassword"

sudo defaults write "/Library/Preferences/com.apple.loginwindow" autoLoginUser "$EBSAdminUser"
sudo defaults write "/Volumes/$targetMountName/Library/Preferences/com.apple.loginwindow" autoLoginUser "aws-managed-user"

# Writes LaunchDaemon to the internal SSD.
echo "$BoosterRocketLaunchDaemon" | sudo tee /tmp/com.amazon.dsx.boosterrocket.credentials.plist
sudo cp "/tmp/com.amazon.dsx.boosterrocket.credentials.plist" "/Volumes/$targetMountName/Library/LaunchDaemons/"

# Writes LaunchAgent to the internal SSD.
echo "$BoosterRocketLaunchAgent" | sudo tee "/tmp/com.amazon.dsx.boosterrocket.plist"
sudo cp "/tmp/com.amazon.dsx.boosterrocket.plist" "/Volumes/$targetMountName/Library/LaunchAgents/"

# Streamline login, eliminates prompts for iCloud.
rm -f /Volumes/$targetMountName/Users/aws-managed-user/Library/Preferences/com.apple.SetupAssistant.plist

    outputPath="/Volumes/$targetMountName/Users/aws-managed-user/Library/Preferences"

cp "/Users/$EBSAdminUser/Library/Preferences/com.apple.SetupAssistant.plist" "$outputPath/"

sudo chown -R 501:20 "$outputPath/com.apple.SetupAssistant.plist"


sudo defaults write "$outputPath/com.apple.screensaver" idleTime 0

# cliclick before reboot
brew install cliclick
cp -L "/opt/homebrew/bin/cliclick" "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/"

# UUID from ByHost: | awk 'BEGIN { FS = "." } ; {print $(NF-1)}'

# Set the ownership and privileges for the LaunchAgent/Daemon and its script.
sudo chown root:wheel "/Volumes/$targetMountName/Library/LaunchAgents/com.amazon.dsx.boosterrocket.plist"
sudo chown root:wheel "/Volumes/$targetMountName/Library/LaunchDaemons/com.amazon.dsx.boosterrocket.credentials.plist"
sudo chmod -R +x "/Volumes/$targetMountName/Users/Shared/.BoosterRocket/"

# Invisible file so BoosterRocket doesn't run twice. Useful for User data!
touch "/Users/Shared/.BoosterRocket.splashdown"

if [ -f "/Users/Shared/.BoosterRocket.autoLoginReboot" ]; then
    sleep 1
else
    touch "/Users/Shared/.BoosterRocket.autoLoginReboot"
    sudo reboot
fi

else
if [ -f "/Users/Shared/.BoosterRocket.autoLoginReboot2" ]; then
    sleep 1
else
    touch "/Users/Shared/.BoosterRocket.autoLoginReboot2"
    sudo reboot
fi

sleep 1

fi
```

### 7. Reset to an initial state : RRV 

**Slide** : None

**Talking Points**:
 
- explain what is RRV + benefits 
- show sequence of commands to initiate a RRV 

```sh
#!/bin/sh

### ChangeTempo: restore a running AWS EC2 instance using Replace Root Volume to a snapshot.
### Reference commands for using RRV via the AWS command line.

PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/opt/homebrew/sbin

MDToken=$(curl -X PUT "http://169.254.169.254/latest/api/token" -s -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
currentInstanceID=$(curl -H "X-aws-ec2-metadata-token: $MDToken" -s http://169.254.169.254/latest/meta-data/instance-id)

### Revert currently-running instance to the state of its AMI at launch.
aws ec2 create-replace-root-volume-task --instance-id $currentInstanceID

### Create a snapshot (for restoration):
aws ec2 create-snapshot --instance-id $currentInstanceID

### To specify the snapshot:
targetSnapshotID="snap-XXXXXXXXXXXXXXXXX"
aws ec2 create-replace-root-volume-task --instance-id $currentInstanceID --snapshot-id $targetSnapshotID

### To replace the root volume with an arbitrary AMI:
targetAMIID="ami-XXXXXXXXXXXXXXXXX"
aws ec2 create-replace-root-volume-task --instance-id $currentInstanceID --image-id $targetAMIID

aws ec2 describe-replace-root-volume-tasks --replace-root-volume-task-ids $taskID
```

### 8. Automate the release of dedicated hosts 

**Slide** : None

**Talking Points**:
 
- bash 
```bash
#!/bin/bash
### Judgement Day: Instance Terminator and Host Releaser, built for EC2 Mac.
### Terminates instances and releases hosts at or after the 24 hour mark of allocation.

### Change this value to one of your IAM instance profiles/roles that can terminate the calling instance.
roleName="EC2JudgementDayRole"

### BEGIN METADATA GATHERING ###

### Retrieves API token for AWS metadata calls.
MDToken=$(curl -X PUT "http://169.254.169.254/latest/api/token" -s -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
### Takes the current instance ID from the instance's metadata.
currentInstanceID=$(curl -H "X-aws-ec2-metadata-token: $MDToken" -s http://169.254.169.254/latest/meta-data/instance-id)
currentHostID=$(curl -H "X-aws-ec2-metadata-token: $MDToken" -s http://169.254.169.254/latest/meta-data/placement/host-id)
hostRegion=$(curl -H "X-aws-ec2-metadata-token: $MDToken" -s http://169.254.169.254/latest/meta-data/placement/region)
currentInstanceProfile=$(curl -H "X-aws-ec2-metadata-token: $MDToken" -s http://169.254.169.254/latest/meta-data/iam/security-credentials)

###  END METADATA GATHERING  ###

# Log to verify the instance and host ID.
echo "EC2 instance to be terminated is $currentInstanceID on $currentHostID."

# Retrieve the allocation time for the current hist, and convert to UNIX epoch time.
hostAllocationTimeRaw=$(aws ec2 describe-hosts --host-id $currentHostID | grep AllocationTime | awk {'print $NF'})
hostAllocationTime=$(echo $hostAllocationTimeRaw | tr -d "\"," | cut -f1 -d "+")
echo "Allocation timestamp: $hostAllocationTime"

hostAllocationEpoch=$(date -jf "%Y-%m-%dT%H:%M:%S" $hostAllocationTime +%s)
echo "Current allocation epoch: $hostAllocationEpoch"

# Value for the earliest instance termination time: 2 minutes before the host is to be released.
instanceTerminationEpoch=$(expr $hostAllocationEpoch + 86280)
echo "Terminate instance at: $instanceTerminationEpoch (2 minutes to spin down)"

# Value for the earliest host release time: 24 hours after the initial allocation time..
hostTerminationEpoch=$(expr $hostAllocationEpoch + 86400)
echo "Release host at: $hostTerminationEpoch"

# Converted string back to format used by AWS CLI, unused outside of readability echo below.
hostTerminationTime=$(date -jf %s $hostTerminationEpoch +"%Y-%m-%dT%H:%M:%S")
# echo "Termination time for API $hostTerminationTime+0:00"

echo "Calculations complete…"
echo "Initial host allocation: $hostAllocationTime"
echo "Earliest host release:   $hostTerminationTime"

currentTime=$(date +%s)
timeDifferential=$(expr $hostTerminationEpoch - $currentTime)

# A rough timer to wait for -180 seconds to release time if allocation time is less than 24 hours.
if [[ $timeDifferential -gt 0 ]] 
then
sleep $(expr $timeDifferential - 180)
fi

# Checks every second and waits until 2 minutes (120 seconds) before host release to spin up t2.micro with instructions to terminate and release at the target time.
while [ $currentTime -lt $instanceTerminationEpoch ]
do
# Uncomment below for debug logging on time epoch differential.
# echo "Host cannot be released yet…" $currentTime vs $instanceTerminationEpoch
sleep 1
currentTime=$(date +%s)
done
echo "Minimum 24 hour lease time elapsed. Cyberdyne to terminate instance $currentInstanceID and release $currentHostID!"

## User data for a t2.nano host called Cyberdyne, script encoded on the fly.
cat << EOF > /tmp/userData.sh
#!/bin/sh
echo "----------BEGIN CYBERDYNE ROUTINES----------"
MDToken=\$(curl -X PUT "http://169.254.169.254/latest/api/token" -s -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
cyberdyneInstanceID=\$(curl -H "X-aws-ec2-metadata-token: \$MDToken" -s http://169.254.169.254/latest/meta-data/instance-id)

hostToTerminate="$currentHostID"

currentTime=\$(date +%s)

awsCLI="/usr/bin/aws"

terminateInstanceOnHost=\$(\$awsCLI ec2 terminate-instances --region $hostRegion --instance-ids $currentInstanceID)

while [ \$currentTime -lt $hostTerminationEpoch ]
do
echo "Waiting to release $currentHostID (\$currentTime vs $hostTerminationEpoch)"
sleep 1
currentTime=\$(date +%s)
done

echo "Time to release $hostToTerminate! (\$currentTime is after $hostTerminationEpoch)"

releaseHost=\$(\$awsCLI ec2 release-hosts --region $hostRegion --host-id $hostToTerminate | tr -d '\n')

echo "Response: \$releaseHost"

successString='{    "Successful": [        "'\$hostToTerminate'"    ],    "Unsuccessful": []}'

retryLimit=4

until  [[ "\$releaseHost" == "\$successString" ]]
do
echo "Releasing host $hostToTerminate... \$c" ; sleep 1
releaseHost=\$(\$awsCLI ec2 release-hosts --host-id $hostToTerminate --region $hostRegion | tr -d '\n')
 ((c++)) && ((c==\$retryLimit)) && break
 echo "Response: \$releaseHost"
done

echo \$currentHostID released!

echo Terminating \$cyberdyneInstanceID...

\$awsCLI ec2 terminate-instances --instance-ids \$cyberdyneInstanceID --region $hostRegion 
echo \$cyberdyneInstanceID terminated! ::thumbsup::

echo "----------END CYBERDYNE ROUTINES----------"
exit 0;
EOF

userDataUp=$(cat /tmp/userData.sh)
tagSpec="ResourceType=instance,Tags=[{Key=Name,Value=Cyberdyne $currentHostID}]"

cyberdyneLaunch=$(aws ec2 run-instances \
    --image-id ami-09d3b3274b6c5d4aa \
    --instance-type t2.nano \
    --iam-instance-profile "Name=$roleName" \
    --user-data "$userDataUp" \
    --tag-specifications "$tagSpec")
    
echo "Cyberdyne launched! ETA to termination/release is ~ 2 minutes."

```
- Lambda + EventBus to schedule a run every 24h

```python
def lambda_handler(event, context):
	print('Received event: ' + json.dumps(event))
  
	ec2 = boto3.client('ec2', region_name='us-east-1') # can be improved

	# search for available hosts 
	# you might want to add a filters on tag as well
	response = ec2.describe_hosts(
		Filters=[
			{
				'Name': 'instance-type',
				'Values': [ 'mac1.metal', 'mac2.metal' ]
			},
			{
				'Name': 'state', 
				'Values': [ 'available' ]
			}
		]
	)

	result = {}

    # when host array is empty, exit
	if len(response['Hosts']) == 0:
		result = "No hosts found"
		result = { 'message' : result }
	else:
		# Filter for hosts with AvailableCapacity 1
		host_ids = [host['HostId'] for host in response['Hosts'] 
			  				if host['AvailableCapacity']['AvailableInstanceCapacity'][0]['AvailableCapacity'] == 1]		
		# release hosts
		print("Releasing hosts: {}".format(host_ids))
		result = ec2.release_hosts(HostIds=host_ids)
	
	return result
```

```swift
    public func release() async throws {
        
        // prepare the request with filters
        let describeHosts = DescribeHostsInput(filter: [.init(name: "instance-type", values: ["mac1.metal", "mac2.metal"]),
                                                        .init(name: "state", values: ["available"])])
        
        // create a client
        let ec2Client = try EC2Client(region: "us-east-1")
        
        // send the request and wait for the result
        let result = try await ec2Client.describeHosts(input: describeHosts)
        
        // verify preconditions on the result
        guard let hosts = result.hosts else {
            throw DedicatedHostReleaserError.noHostsInResult
        }
        guard hosts.count > 0 else {
            throw DedicatedHostReleaserError.noHostSelected
        }
        
        // iterate on the results
        hosts.forEach { host in
            print(host.hostId ?? "unknown host id")
        }
        
        // Filter for hosts with AvailableCapacity 1
        let hostEligibles = hosts.filter { host in
            host.availableCapacity?.availableInstanceCapacity?[0].availableCapacity == 1
        }.map { host in
            host.hostId ?? "unknow id"
        }
        
        //        self.logger.trace("Releasing Hosts", metadata: ["hostIds":hostEligibles.join(separator:",")])
        
        let releaseRequest = ReleaseHostsInput(hostIds: hostEligibles)
        let _ = try await ec2Client.releaseHosts(input: releaseRequest)
    }
}
```

### 9. Recap and CTA 

**Slide** : #4

**Talking Points**:
 
- (mostly) everything can be scripted. Including things that can not be scripted with physical machines
- start to automate your usage of EC2 Mac today !

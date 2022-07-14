# Automated Forensics Orchestrator for Amazon EC2

Automated Forensics Orchestrator for Amazon EC2 is a self-service AWS Solution implementation that enterprise customers can deploy to quickly set up and configure an automated orchestration workflow that enables their Security Operations Centre (SOC) to capture and examine data from EC2 instances and attached volumes as evidence for forensic analysis, in the event of a potential security breach. It will orchestrate the forensics process from the point at which a threat is first detected, enable isolation of the affected EC2 instances and data volumes, capture memory and disk images to secure storage, and trigger automated actions or tools for investigation and analysis of such artefacts. All the while, the solution will notify and report on its progress, status, and findings. It will enable SOC to continuously discover and analyze patterns of fraudulent activities across multi-account and multi-region environments. The solution will leverage native AWS services and be underpinned by a highly available, resilient, and serverless architecture, security, and operational monitoring features.

Digital forensics is a 4 step process of triaging, acquisition, analysis and reporting. Automated Forensics framework provides capability to enterprise to act on security event by imaging or acquisition of breached resource for examination and generate forensic report about the security breach. In the event of a security breach, it will enable customers to easily to capture and examine required targeted data for forsensic’s storage and analysis. This solution framework enables security operations centre to discover and analyse patterns of fraudulent activities. The automated forensics solution will provide a multi-account and a multi-region [“solution”] built using native AWS services.

### Automated Forensics Orchestrator for Amazon EC2 Solution Architecture

![Forensic Orchestrator Architecture](architecture/architecture.png)

---

## Build and Deploy Forensic Stack :

### Prerequisites

_Tools_

    * The latest version of the AWS CLI (2.2.37 or newer), installed and configured.
        * https://aws.amazon.com/cli/
    * The latest version of the AWS CDKV2 (2.2 or newer).
        * https://docs.aws.amazon.com/cdk/latest/guide/home.html
    * A CDK bootstrapped AWS account.
        * https://docs.aws.amazon.com/cdk/latest/guide/bootstrapping.html
    * nodejs version 16
            * https://docs.npmjs.com/getting-started
            *
    * LIME agent installed on EC2
    * SecurityHub needs to be enabled as the solution creates custom action in securityHub
        *NOTE:* a blog detailing how to use SSM Distributor to deploy agents across a multi account env is in the pipeline. Waiting the eta for publication to potentially use as a reference.
    * EC2 instances supported
        * *Amazon Linux 2 AMI (HVM) - Kernel 5.10, SSD Volume Type* - ami-0a4e637babb7b0a86 (64-bit x86) / ami-0bc96915949503483 (64-bit Arm)

### Build and deploy in New VPC

### Forensic Account deployment:

1. Clone the solution source code from its GitHub repository.
    1. git clone https://github.com/aws-solutions/automated-forensic-orchestrator-for-amazon-ec2.git
2. Open the terminal and navigate to the folder created in step 1.
3. Navigate to the source folder
4. Configure your application accounts monitored to establish trust relationship in cdk.json
    1. "applicationAccounts": ["<<Application account1>>", "<<Application account2>>"],
5. Set AWS Credentials to deploy into the AWS Account
    1. export AWS_ACCESS_KEY_ID=<<XXXXXXXXXXXXXXXX>>
    2. export AWS_SECRET_ACCESS_KEY=<<XXXXXXXXXXXXXXXXXXX>>
    3. export AWS_SESSION_TOKEN=<<XXXXXXXXXXXXXXXXX>>
    4. export AWS_REGION=<<AWS Region - us-east-1>>
6. Run _npm ci_
7. Run _npm run build-lambda_
8. Run* npm run build:collector*
9. _Steps to build the Forensic Stack to be deployed in Forensic AWS Account_
    -   - `cdk synth -c account=<<Forensic AWS Account>> -c region=<<region>> -c secHubAccount=<<SecuHub Aggregator Account>> -c STACK_BUILD_TARGET_ACCT=forensicAccount` build the necessary CDK CFN templates for deploying forensic stack
    1. _Example:_ cdk synth -c account=1234567890 -c secHubAccount=0987654321 -c region=us-east-1 -c STACK_BUILD_TARGET_ACCT=forensicAccount
10. _Steps to deploy the Forensic Stack to be deployed in Forensic AWS Account_

    -   - `cdk deploy --all -c account=<<Forensic AWS Account>> -c region=us-east-1 --require-approval=never -c secHubAccount=<<SecuirtyHub Aggregator AWS Account>>` Deploy the necessary CDK CFN templates for deploying Forensic Solutions stack

    1. _Example_: cdk deploy ——all -c secHubAccount=0987654321 -c STACK_BUILD_TARGET_ACCT=forensicAccount -c account=1234567890 -c region=ap-southeast-2 —require-approval=never

### SecurityHub Aggregator Account Deployment in New VPC :

To push Forensic findings into Forensic Account following stack needs to be deployed in SecurityHub Aggregator account
_Note_: if you are reusing the above git clone kindly delete the cdk.out folder

1. Clone the solution source code from its GitHub repository.
    1. git clone https://github.com/aws-solutions/automated-forensic-orchestrator-for-amazon-ec2.git
2. Open the terminal and navigate to the folder created in step 1.
3. Navigate to the source folder
4. Set AWS Credentials to deploy into the AWS Account
    1. export AWS_ACCESS_KEY_ID=<<XXXXXXXXXXXXXXXX>>
    2. export AWS_SECRET_ACCESS_KEY=<<XXXXXXXXXXXXXXXXXXX>>
    3. export AWS_SESSION_TOKEN=<<XXXXXXXXXXXXXXXXX>>
    4. export AWS_REGION=<<AWS Region - us-east-1>>
5. Run _npm ci_
6. Run _npm run build-lambda_
7. Run* npm run build:collector*
8. _Steps to build the Forensic Stack to be deployed in SecurityHub Aggregator Account_
   cdk synth -c sechubaccount=<<SecHub Account>> -c forensicAccount=<<Forensic Account>> -c forensicRegion=us-east-1 -c sechubregion=us-east-1 -c STACK_BUILD_TARGET_ACCT=securityHubAccount
    1. _EXAMPLE_:
       cdk synth -c sechubaccount=0987654321 -c forensicAccount=1234567890 -c forensicRegion=us-east-1 -c sechubregion=us-east-1 -c STACK_BUILD_TARGET_ACCT=securityHubAccount
9. _Steps to Deploy the Forensic Stack to be deployed in SecurityHub Aggregator Account_

    cdk deploy --all -c account=<<SecuirtyHub AWS Account>> -c region=us-east-1 --require-approval=never -c forensicAccount=<<Forensic AWS Account>>` Deploy the necessary CDK CFN templates for deploying SecurityHub stack

    1. _EXAMPLE_:
       cdk deploy --all -c account=0987654321 -c region=us-east-1 --require-approval=never -c forensicAccount=1234567890` Deploy the necessary CDK CFN templates for deploying SecurityHub stack

### Application account Account Deployment :

1. Deploy the following cloud formation template in Application account to establish trust relationship between forensic components deployed in forensic account and application account
    1. Cloud formation template is available in folder
        1. Aws-compute-forensics-solution/deployment-prerequisties/cross-account-role.yml
    2. Pass the forensic account as input parameter - solutionInstalledAccount

## Build and deploy in Existing VPC

### Forensic Account deployment

1. Clone the solution source code from its GitHub repository.
2. Open the terminal and navigate to the folder created in step 1.
3. Navigate to the source folder
4. update cdk.json to configure isExistingVPC to true and add vpcID to the vpcConfigDetails cdk.json
    1. "vpcConfigDetails": {
       "isExistingVPC": true,
       "vpcID": "vpc-1234567890"
       "enableVPCEndpoints": false,
       "enableVpcFlowLog": false
       }
5. Configure your application accounts monitored to establish trust relationship in cdk.json
    1. "applicationAccounts": ["<<Application account1>>", "<<Application account2>>"],
6. Set AWS Credentials to deploy into the AWS Account
    1. export AWS_ACCESS_KEY_ID=<<XXXXXXXXXXXXXXXX>>
    2. export AWS_SECRET_ACCESS_KEY=<<XXXXXXXXXXXXXXXXXXX>>
    3. export AWS_SESSION_TOKEN=<<XXXXXXXXXXXXXXXXX>>
    4. export AWS_REGION=<<AWS Region - us-east-1>>
7. Run _npm ci_
8. Run _npm run build-lambda_
9. Run* npm run build:collector*
10. _Steps to build the Forensic Stack to be deployed in Forensic AWS Account_
    -   - `cdk synth -c account=<<Forensic AWS Account>> -c region=<<region>> -c secHubAccount=<<SecuHub Aggregator Account>> -c STACK_BUILD_TARGET_ACCT=forensicAccount` build the necessary CDK CFN templates for deploying forensic stack
    1. _Example:_ cdk synth -c account=1234567890 -c secHubAccount=0987654321 -c region=us-east-1 -c STACK_BUILD_TARGET_ACCT=forensicAccount
11. _Steps to deploy the Forensic Stack to be deployed in Forensic AWS Account_

    -   - `cdk deploy --all -c account=<<Forensic AWS Account>> -c region=ap-southeast-2 --require-approval=never -c secHubAccount=<<SecuirtyHub Aggregator AWS Account>>` Deploy the necessary CDK CFN templates for deploying Forensic Solutions stack

    1. _Example_: cdk deploy —all -c secHubAccount=0987654321 -c STACK_BUILD_TARGET_ACCT=forensicAccount -c account=1234567890 -c region=ap-southeast-2 —require-approval=never

### SecurityHub Aggregator Account Deployment in Existing VPC

To push Forensic findings into Forensic Account following stack needs to be deployed in SecurityHub Aggregator account
_Note_: if you are reusing the above git clone kindly delete the cdk.out folder

1. Clone the solution source code from its GitHub repository.
2. Open the terminal and navigate to the folder created in step 1.
3. Navigate to the source folder
4. update cdk.json to configure isExistingVPC to true and add vpcID to the vpcConfigDetails cdk.json
    1. "vpcConfigDetails": {
       "isExistingVPC": true,
       "vpcID": "vpc-1234567890"
       "enableVPCEndpoints": false,
       "enableVpcFlowLog": false
       }
5. Set AWS Credentials to deploy into the AWS Account
    1. export AWS_ACCESS_KEY_ID=<<XXXXXXXXXXXXXXXX>>
    2. export AWS_SECRET_ACCESS_KEY=<<XXXXXXXXXXXXXXXXXXX>>
    3. export AWS_SESSION_TOKEN=<<XXXXXXXXXXXXXXXXX>>
    4. export AWS_REGION=<<AWS Region - us-east-1>>
6. Run _npm ci_
7. Run _npm run build-lambda_
8. Run* npm run build:collector*
9. _Steps to build the Forensic Stack to be deployed in SecurityHub Aggregator Account_
   cdk synth -c sechubaccount=<<SecHub Account>> -c forensicAccount=<<Forensic Account>> -c forensicRegion=ap-southeast-2 -c sechubregion=ap-southeast-2 -c STACK_BUILD_TARGET_ACCT=securityHubAccount
    1. _EXAMPLE_:
       cdk synth -c sechubaccount=0987654321 -c forensicAccount=1234567890 -c forensicRegion=ap-southeast-2 -c sechubregion=ap-southeast-2 -c STACK_BUILD_TARGET_ACCT=securityHubAccount
10. _Steps to Deploy the Forensic Stack to be deployed in SecurityHub Aggregator Account_

    cdk deploy --all -c account=<<SecuirtyHub AWS Account>> -c region=ap-southeast-2 --require-approval=never -c forensicAccount=<<Forensic AWS Account>>` Deploy the necessary CDK CFN templates for deploying SecurityHub stack

    1. _EXAMPLE_:
       cdk deploy --all -c account=0987654321 -c region=ap-southeast-2 --require-approval=never -c forensicAccount=1234567890` Deploy the necessary CDK CFN templates for deploying SecurityHub stack

### Application account Account Deployment

1. Deploy the following cloud formation template in Application account to establish trust relationship between forensic components deployed in forensic account and application account
    1. Cloud formation template is available in folder
        1. Aws-compute-forensics-solution/deployment-prerequisties/cross-account-role.yml
    2. Pass the forensic account as input parameter - solutionInstalledAccount

## Uninstall the solution

The solution can be uninstalled by either

-   Run cdk destroy --all from the sources folder.
-   Delete the stack from the CloudFormation console.

_Using the AWS Management Console_

        1. Sign in to the AWS CloudFormation console.
        2. Select this solution’s installation stack.
        3. Choose *Delete*.

## Getting CDK Synth Working

1. Ensure `pip` is available in the CLI
    1. You can install Pip from [here](https://www.python.org/downloads/)
    1. If you don't get `pip` through the CLI, check if you have `pip3` available by typing the command `pip3 -V`
    1. For OhMyZsh users, you can create an alias to Pip3, follow this [article](https://stackoverflow.com/questions/42870537/zsh-command-cannot-found-pip)
    1. For other terminals please update this ReadMe.md file as required
1. Navigate to the `aws-compute-forensics-solution/source` directory and open a terminal there
1. Now you can run `make virtualenv` from the prompt
1. Activate the virtual environment by running `source .venv/bin/activate`
1. Download all dependencies using `make install`
1. You can now either run `cdk synth` or `npm run all`

## Steps to set up Python Environment

1. Follow and install pyenv - https://github.com/pyenv/pyenv
1. For zsh - run: source ~/.zshrc (Ensure eval “$(pyenv init --path)” is set)
1. For bash - run: source ~/.bashrc
1. Check the correct Python version is available via pyenv using the command `pyenv versions`
1. If you don't see a version of 3.8.0 or greater you can install it using `pyenv install XXX` where XXX is the python version
1. Set that new version as the default pyenv version if needed using `pyenv global XXX`
1. Check for python environment is set properly Run python --version the output should be Python 3.8.x and above

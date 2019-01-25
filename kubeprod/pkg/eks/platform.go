/*
 * Bitnami Kubernetes Production Runtime - A collection of services that makes it
 * easy to run production workloads in Kubernetes.
 *
 * Copyright 2019 Bitnami
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

func (conf *Config) getAwsSession() *session.Session {
	if conf.session == nil {
		conf.session = session.Must(session.NewSession())
	}
	return conf.session
}

// Retrieves the identity of the caller. Among other details retrieves
// the AWS account number.
func (conf *Config) getCallerIdentity() *sts.GetCallerIdentityOutput {
	svc := sts.New(conf.getAwsSession())
	input := &sts.GetCallerIdentityInput{}

	result, err := svc.GetCallerIdentity(input)
	if err != nil {
		log.Panicf("Error retrieving caller identity\n%v", err)
	}
	return result
}

// Creates a new hosted zone in Route 53 if required, or reuses an existing
// one that matches the fully-qualified name for the DNS zone to be used by
// BKPR.
func (conf *Config) createHostedZone() string {
	DNSZone := conf.DNSZone
	if !strings.HasSuffix(DNSZone, ".") {
		DNSZone = DNSZone + "."
	}

	listInput := &route53.ListHostedZonesByNameInput{
		DNSName:  aws.String(DNSZone),
		MaxItems: aws.String("1"),
	}
	svc := route53.New(conf.getAwsSession())
	listResult, err := svc.ListHostedZonesByName(listInput)
	if err != nil {
		log.Panicf("Error listing Route 53 zone named: %s: %v", DNSZone, err)
	}
	log.Debugf("Hosted zone in Route 53: %s", listResult.GoString())
	if len(listResult.HostedZones) > 0 && *listResult.HostedZones[0].Name == DNSZone {
		// Returns the ZONEID from the "/hostedzone/<ZONEID>" string
		hostedZoneID := strings.Split(*listResult.HostedZones[0].Id, "/")[2]
		log.Warningf("Re-using exting Route 53 hosted zone for External DNS integration: %s", DNSZone)
		return hostedZoneID
	}

	// Create the hosted zone in Route 53
	UUID := strings.ToUpper(uuid.New().String())
	createInput := &route53.CreateHostedZoneInput{
		CallerReference: aws.String(UUID),
		Name:            aws.String(DNSZone),
	}
	createResult, err := svc.CreateHostedZone(createInput)
	if err != nil {
		log.Panicf("Error creating Route 53 zone named: %s: %v", DNSZone, err)
	}
	// Returns the ZONEID from the "/hostedzone/<ZONEID>" string
	return strings.Split(*createResult.HostedZone.Id, "/")[2]
}

// Creates a new user policy (or reuses the existing one) in AWS to allow
// for integration between External DNS and the corresponding hosted zone
// in Route 53 zone. The user policy is named like "bbkpr-${dnsZone}".
func (conf *Config) getUserPolicy() *string {
	type StatementEntry struct {
		Effect   string
		Action   []string
		Resource string
	}

	type PolicyDocument struct {
		Version   string
		Statement []StatementEntry
	}

	// Creates (or reuses) the hosted zone in Route 53 to be used for
	// integration with External DNS
	hostedZoneID := conf.createHostedZone()

	policy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []StatementEntry{
			StatementEntry{
				Effect: "Allow",
				Action: []string{
					"route53:GetHostedZone",
					"route53:GetHostedZoneCount",
					"route53:ListHostedZones",
					"route53:ListHostedZonesByName",
					"route53:ListResourceRecordSets",
				},
				Resource: "*",
			},
			StatementEntry{
				Effect: "Allow",
				// Allows for DeleteItem, GetItem, PutItem, Scan, and UpdateItem
				Action: []string{
					"route53:ChangeResourceRecordSets",
				},
				Resource: fmt.Sprintf("arn:aws:route53:::hostedzone/%s", hostedZoneID),
			},
		},
	}

	b, err := json.Marshal(&policy)
	if err != nil {
		log.Panicf("Error marshaling policy\n%v", err)
	}

	svc := iam.New(conf.getAwsSession())
	policyName := aws.String(fmt.Sprintf("bkpr-%s", conf.DNSZone))
	result, err := svc.CreatePolicy(&iam.CreatePolicyInput{
		PolicyDocument: aws.String(string(b)),
		PolicyName:     policyName,
	})

	if err == nil {
		// Return ARN of the previously created policy object
		log.Info("Created IAM policy for External DNS integration: ", *result.Policy.Arn)
		return result.Policy.Arn
	}

	// Check why the request to create the IAM policy failed...
	if aerr, ok := err.(awserr.Error); ok {
		if aerr.Code() == iam.ErrCodeEntityAlreadyExistsException {
			log.Warning("Re-using existing IAM policy for External DNS integration: ", *policyName)
			callerIdentity := conf.getCallerIdentity()
			arn := &arn.ARN{
				Partition: "aws",
				Service:   "iam",
				AccountID: *callerIdentity.Account,
				Resource:  fmt.Sprintf("policy/%s", *policyName),
			}
			input := &iam.GetPolicyInput{
				PolicyArn: aws.String(arn.String()),
			}
			result, err := svc.GetPolicy(input)
			if err != nil {
				log.Panicf("Error looking up IAM policy with ARN %v\n%v", arn, err)
			}
			// Store ARN of the existing policy object
			return result.Policy.Arn
		}
	}

	// Unable to handle any other errors.
	log.Panicf("Error creating IAM policy\n%v", err)
	return nil
}

// Attaches the correct IAM policy to the user used for integration with
// External DNS.
func (conf *Config) attachUserPolicy() {
	// Retrieve the ARN for the policy that limits the privileges for
	// the user to be used for External DNS integration
	policyArn := conf.getUserPolicy()
	userName := fmt.Sprintf("bkpr-%s", conf.DNSZone)
	log.Debugf("Policy ARN: %s", *policyArn)

	aupInput := &iam.AttachUserPolicyInput{
		PolicyArn: policyArn,
		UserName:  aws.String(userName),
	}
	svc := iam.New(conf.getAwsSession())
	_, err := svc.AttachUserPolicy(aupInput)
	if err != nil {
		log.Panicf("Error attaching policy %s to user %s\n%v", *policyArn, userName, err)
	} else {
		log.Info("Attached IAM policy for External DNS integration")
	}
}

// Creates a new user (or reuses the existing one) in AWS to allow
// for integration between External DNS and a hosted Route53 zone.
// The user is named like "bbkpr-${dnsZone}" and will get an IAM
// policy attached to it which limits R/W to the hosted Route53 zone
// to be used by BKPR and R/O for any other zones. The IAM policy
// will be created if necessary.
func (conf *Config) createAwsUser() (string, string) {
	userName := fmt.Sprintf("bkpr-%s", conf.DNSZone)

	// Create an AWS user
	userInput := &iam.CreateUserInput{
		UserName: aws.String(userName),
		Tags: []*iam.Tag{
			{
				Key:   aws.String("created_by"),
				Value: aws.String("bkpr"),
			},
		},
	}

	svc := iam.New(conf.getAwsSession())
	_, err := svc.CreateUser(userInput)
	if err != nil {
		log.Warning("Re-using existing AWS user for External DNS integration: ", userName)
	} else {
		log.Infof("Created AKS user: %s", userName)
	}

	conf.attachUserPolicy()

	// Create/Add an Access Key
	akInput := &iam.CreateAccessKeyInput{
		UserName: aws.String(userName),
	}
	ak, err := svc.CreateAccessKey(akInput)
	if err != nil {
		log.Panicf("Cannot create AWS access key for External DNS integration\n%v", err)
	}
	return *ak.AccessKey.AccessKeyId, *ak.AccessKey.SecretAccessKey
}

// Configuration for integration between External DNS and AWS.
func (conf *Config) setUpExternalDNS() error {
	log.Info("Setting up configuration for External DNS")
	flags := conf.flags

	if conf.ExternalDNS.AWSAccessKeyID == "" {
		AWSAccessKeyID, err := flags.GetString(flagAWSAccessKeyID)
		if err != nil {
			return err
		}
		conf.ExternalDNS.AWSAccessKeyID = AWSAccessKeyID
	}
	if conf.ExternalDNS.AWSSecretAccessKey == "" {
		AWSSecretAccessKey, err := flags.GetString(flagAWSSecretAccessKey)
		if err != nil {
			return err
		}
		conf.ExternalDNS.AWSSecretAccessKey = AWSSecretAccessKey
	}

	// At this point, if the AWS secret is still empty, try to create an AWS
	// access key for a user named "bkpr.${dnsZone}"
	if conf.ExternalDNS.AWSAccessKeyID == "" || conf.ExternalDNS.AWSSecretAccessKey == "" {
		conf.ExternalDNS.AWSAccessKeyID, conf.ExternalDNS.AWSSecretAccessKey = conf.createAwsUser()
	}
	return nil
}

// Generate platform configuration
func (conf *Config) Generate(ctx context.Context) error {
	flags := conf.flags

	if conf.DNSZone == "" {
		domain, err := flags.GetString(flagDNSSuffix)
		if err != nil {
			return err
		}
		conf.DNSZone = domain
	}

	if conf.DNSZone != "" {
		//
		// External DNS setup
		//
		err := conf.setUpExternalDNS()
		if err != nil {
			return err
		}
	}

	//
	// oauth2-proxy setup
	//
	if conf.OauthProxy.ClientID == "" || conf.OauthProxy.ClientSecret == "" {
		// TODO
	}

	return nil
}

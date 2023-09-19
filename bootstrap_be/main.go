package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sync"

	"cloud.google.com/go/compute/metadata"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

var ()

func main() {

	defaultProjectID := "YOUR_PROJECT_ID" // change this

	ctx := context.Background()

	if metadata.OnGCE() {
		var err error
		defaultProjectID, err = metadata.ProjectID()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}

	err := os.Mkdir("/envoy", os.ModePerm)
	if err != nil {
		log.Println(err)
	}

	err = os.Mkdir("/consul", os.ModePerm)
	if err != nil {
		log.Println(err)
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer client.Close()

	//  /envoy/ca.pem
	accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/ca/versions/latest", defaultProjectID),
	}

	result, err := client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	err = ioutil.WriteFile("/envoy/ca.pem", result.Payload.Data, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// /envoy/be.crt
	accessRequest = &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/be-cert/versions/latest", defaultProjectID),
	}

	result, err = client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	err = ioutil.WriteFile("/envoy/be.crt", result.Payload.Data, 0644)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// /envoy/be.key
	accessRequest = &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/be-key/versions/latest", defaultProjectID),
	}

	result, err = client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	err = ioutil.WriteFile("/envoy/be.key", result.Payload.Data, 0644)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// consul-agent-ca
	accessRequest = &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/consul-agent-ca/versions/latest", defaultProjectID),
	}

	result, err = client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	err = ioutil.WriteFile("/consul/consul-agent-ca.pem", result.Payload.Data, 0644)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// be_config.json
	accessRequest = &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/be_config/versions/latest", defaultProjectID),
	}

	result, err = client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	err = ioutil.WriteFile("/consul/be_config.json", result.Payload.Data, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// be_agent-hcl
	accessRequest = &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/be_agent-hcl/versions/latest", defaultProjectID),
	}

	result, err = client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	err = ioutil.WriteFile("/consul/be_agent.hcl", result.Payload.Data, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// ***************************************************************************************************

	// now that we have the keypair written to a file, launch envoy with a configuration
	// that will use those keys

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		cmd := exec.Command("/usr/local/bin/envoy", "-c", "/envoy/be_proxy.yaml")
		var stdBuffer bytes.Buffer
		mw := io.MultiWriter(os.Stdout, &stdBuffer)

		cmd.Stdout = mw
		cmd.Stderr = mw

		if err := cmd.Run(); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Println(stdBuffer.String())
		err = cmd.Wait()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}()

	go func() {
		defer wg.Done()
		cmd := exec.Command("/usr/local/bin/consul", "agent", "-config-dir=/consul")
		var stdBuffer bytes.Buffer
		mw := io.MultiWriter(os.Stdout, &stdBuffer)

		cmd.Stdout = mw
		cmd.Stderr = mw

		if err := cmd.Run(); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Println(stdBuffer.String())
		err = cmd.Wait()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}()

	go func() {
		defer wg.Done()
		cmd := exec.Command("/server", "--port", ":18082")
		var stdBuffer bytes.Buffer
		mw := io.MultiWriter(os.Stdout, &stdBuffer)

		cmd.Stdout = mw
		cmd.Stderr = mw

		if err := cmd.Run(); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Println(stdBuffer.String())
		err = cmd.Wait()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}()

	wg.Wait()
	fmt.Println("Process completed.")

}

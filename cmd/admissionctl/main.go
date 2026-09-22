// Command admissionctl loads a policy document (v1 or v2) and evaluates
// the resources given in a JSON file, printing the explained decision for
// each resource to stdout.
//
// Usage:
//
//	admissionctl -policy policies.json -resources resources.json
//
// resources.json shape: {"resources": [ {Resource}, ... ]}.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lisama569/admission-policy-engine-go/pkg/loader"
	"github.com/lisama569/admission-policy-engine-go/pkg/policy"
)

type resourceBatch struct {
	Resources []*policy.Resource `json:"resources"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "admissionctl:", err)
		os.Exit(1)
	}
}

func run() error {
	policyPath := flag.String("policy", "", "path to the policy document (v1 or v2)")
	resourcesPath := flag.String("resources", "", "path to a JSON file containing {\"resources\":[...]}")
	flag.Parse()
	if *policyPath == "" || *resourcesPath == "" {
		flag.Usage()
		return fmt.Errorf("both -policy and -resources are required")
	}

	rawPolicy, err := os.ReadFile(*policyPath)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	set, err := loader.Load(rawPolicy)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	engine, err := policy.NewEngine(set)
	if err != nil {
		return fmt.Errorf("init engine: %w", err)
	}

	rawResources, err := os.ReadFile(*resourcesPath)
	if err != nil {
		return fmt.Errorf("read resources: %w", err)
	}
	var batch resourceBatch
	if err := json.Unmarshal(rawResources, &batch); err != nil {
		return fmt.Errorf("parse resources: %w", err)
	}

	results := make([]policy.Result, 0, len(batch.Resources))
	for i, r := range batch.Resources {
		res := engine.Evaluate(r)
		results = append(results, res)
		fmt.Fprintf(os.Stderr, "[%d] resource %s/%s kind=%s -> %s\n  reason: %s\n",
			i, r.Namespace, r.Name, r.Kind, res.Decision, res.Reason)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

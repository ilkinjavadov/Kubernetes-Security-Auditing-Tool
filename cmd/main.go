package main

import (
    "flag"
    "fmt"
    "os"
    "kube-sec-audit/pkg/kubeaudit"
    "kube-sec-audit/pkg/imagescanner"
    "kube-sec-audit/pkg/secretdetector"
    "kube-sec-audit/pkg/rbac"
    "kube-sec-audit/pkg/podsec"
    "kube-sec-audit/pkg/netpol"
    "kube-sec-audit/pkg/imagecheck"
    "kube-sec-audit/pkg/reporter"

    "k8s.io/client-go/tools/clientcmd"
)

func main() {
    kubeconfig := flag.String("k", "", "Path to kubeconfig file")
    modules := flag.String("m", "all", "Comma separated list of modules to run: all,kubeaudit,imagescanner,secrets,rbac,podsec,netpol,imagecheck")
    output := flag.String("o", "report.json", "Output report file path (JSON)")

    flag.Parse()

    if *kubeconfig == "" {
        fmt.Println("Please specify kubeconfig path with -k")
        os.Exit(1)
    }

    config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
    if err != nil {
        fmt.Println("Error loading kubeconfig:", err)
        os.Exit(1)
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        fmt.Println("Error creating clientset:", err)
        os.Exit(1)
    }

    report := reporter.NewReport("kube-sec-audit", "v0.1", "cluster")

    runModules := map[string]bool{}
    if *modules == "all" {
        runModules = map[string]bool{
            "kubeaudit":    true,
            "imagescanner": true,
            "secrets":      true,
            "rbac":        true,
            "podsec":      true,
            "netpol":      true,
            "imagecheck":  true,
        }
    } else {
        for _, m := range strings.Split(*modules, ",") {
            runModules[m] = true
        }
    }

    if runModules["kubeaudit"] {
        fmt.Println("Running kubeaudit...")
        if err := kubeaudit.Run(clientset, report); err != nil {
            fmt.Println("kubeaudit error:", err)
        }
    }

    if runModules["imagescanner"] {
        fmt.Println("Running image scanner...")
        if err := imagescanner.ScanImages(clientset, report); err != nil {
            fmt.Println("imagescanner error:", err)
        }
    }

    if runModules["secrets"] {
        fmt.Println("Running secrets detector...")
        if err := secretdetector.ScanSecrets(clientset, report); err != nil {
            fmt.Println("secretdetector error:", err)
        }
    }

    if runModules["rbac"] {
        fmt.Println("Running RBAC analyzer...")
        if err := rbac.AnalyzeRBAC(clientset, report); err != nil {
            fmt.Println("rbac error:", err)
        }
    }

    if runModules["podsec"] {
        fmt.Println("Running pod security context analyzer...")
        if err := podsec.AnalyzePodSecurity(clientset, report); err != nil {
            fmt.Println("podsec error:", err)
        }
    }

    if runModules["netpol"] {
        fmt.Println("Running network policy analyzer...")
        if err := netpol.AnalyzeNetworkPolicies(clientset, report); err != nil {
            fmt.Println("netpol error:", err)
        }
    }

    if runModules["imagecheck"] {
        fmt.Println("Running image & tag risk scanner...")
        if err := imagecheck.AnalyzeImages(clientset, report); err != nil {
            fmt.Println("imagecheck error:", err)
        }
    }

    err = report.SaveAsJSON(*output)
    if err != nil {
        fmt.Println("Failed to save report:", err)
        os.Exit(1)
    }

    fmt.Printf("Audit completed. Report saved to %s\n", *output)
}

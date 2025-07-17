package main

import (
    "fmt"
    "os"
    "strings"

    "github.com/spf13/cobra"
    "kube-sec-audit/pkg/clusterconfig"
    "kube-sec-audit/pkg/podsecurity"
    "kube-sec-audit/pkg/imagescanner"


)

var (
    modules    string
    kubeconfig string
)

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Run security scans on Kubernetes cluster",
    Run: func(cmd *cobra.Command, args []string) {
        if kubeconfig == "" {
            fmt.Println("Please provide --kubeconfig flag with the path to your kubeconfig file.")
            os.Exit(1)
        }
        mods := strings.Split(modules, ",")
        for _, mod := range mods {
            switch mod {
            case "clusterconfig":
                scanner, err := clusterconfig.NewScanner(kubeconfig)
                if err != nil {
                    fmt.Printf("Failed to init clusterconfig scanner: %v\n", err)
                    os.Exit(1)
                }
                if err := scanner.ScanClusterRoleBindings(); err != nil {
                    fmt.Printf("Error scanning ClusterRoleBindings: %v\n", err)
                    os.Exit(1)
                }
            default:
                fmt.Printf("Module %s not implemented yet.\n", mod)


case "podsecurity":
    scanner, err := podsecurity.NewScanner(kubeconfig)
    if err != nil {
        fmt.Println("Error initializing podsecurity scanner:", err)
        os.Exit(1)
    }
    err = scanner.ScanPodsSecurity()
    if err != nil {
        fmt.Println("Error scanning pods:", err)
        os.Exit(1)

case "imagescanner":
    scanner, err := imagescanner.NewScanner(kubeconfig)
    if err != nil {
        fmt.Println("Error initializing image scanner:", err)
        os.Exit(1)
    }
    err = scanner.ScanImages()
    if err != nil {
        fmt.Println("Error scanning images:", err)
        os.Exit(1)
    }



    }
            }
        }
    },
}

func init() {
    scanCmd.Flags().StringVarP(&modules, "modules", "m", "", "Comma-separated list of modules to scan (e.g. clusterconfig,podsecurity)")
    scanCmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "Path to kubeconfig file")
}

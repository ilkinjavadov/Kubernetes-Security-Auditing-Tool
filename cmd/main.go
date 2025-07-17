package main

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
)

func main() {
    rootCmd := &cobra.Command{
        Use:   "kube-sec-audit",
        Short: "Kubernetes Security Auditing Tool",
        Long:  `Comprehensive Kubernetes security scanner with modular design.`,
    }

    rootCmd.AddCommand(scanCmd)

    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

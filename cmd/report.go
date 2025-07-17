package main

import (
    "fmt"
    "kube-sec-audit/pkg/reporter"
    "os"
)

func main() {
    r := reporter.NewReport("kube-sec-audit", "v0.1", "demo-cluster")

    r.AddFinding(reporter.Finding{
        Module:    "secrets",
        Namespace: "default",
        Resource:  "db-password",
        RiskLevel: "high",
        Message:   "Hardcoded password found in Secret",
    })

    r.AddFinding(reporter.Finding{
        Module:    "kubeaudit",
        Namespace: "kube-system",
        Resource:  "kube-proxy",
        RiskLevel: "medium",
        Message:   "Container running as root",
    })

    err := r.SaveAsJSON("output/report.json")
    if err != nil {
        fmt.Println("❌ Failed to save report:", err)
        os.Exit(1)
    }

    r.PrintSummary()
}

package reporter

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
)

type Report struct {
    ToolName   string        `json:"tool"`
    Version    string        `json:"version"`
    Generated  time.Time     `json:"generated_at"`
    Cluster    string        `json:"cluster"`
    Findings   []Finding     `json:"findings"`
}

type Finding struct {
    Module     string `json:"module"`
    Namespace  string `json:"namespace,omitempty"`
    Resource   string `json:"resource"`
    RiskLevel  string `json:"risk"`
    Message    string `json:"message"`
}

func NewReport(toolName, version, cluster string) *Report {
    return &Report{
        ToolName:  toolName,
        Version:   version,
        Cluster:   cluster,
        Generated: time.Now(),
        Findings:  []Finding{},
    }
}

func (r *Report) AddFinding(f Finding) {
    r.Findings = append(r.Findings, f)
}

func (r *Report) SaveAsJSON(path string) error {
    file, err := os.Create(path)
    if err != nil {
        return err
    }
    defer file.Close()

    enc := json.NewEncoder(file)
    enc.SetIndent("", "  ")
    return enc.Encode(r)
}

func (r *Report) PrintSummary() {
    fmt.Printf("✅ Report for %s (%d findings)\n", r.Cluster, len(r.Findings))
    for _, f := range r.Findings {
        fmt.Printf("[%s] %s: %s (%s)\n", f.Module, f.Resource, f.Message, f.RiskLevel)
    }
}

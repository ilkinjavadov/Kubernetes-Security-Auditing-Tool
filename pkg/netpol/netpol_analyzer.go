package netpol

import (
    "context"
    "fmt"
    "kube-sec-audit/pkg/reporter"

    networkingv1 "k8s.io/api/networking/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

func AnalyzeNetworkPolicies(clientset *kubernetes.Clientset, report *reporter.Report) error {
    namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return err
    }

    for _, ns := range namespaces.Items {
        netpols, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(context.TODO(), metav1.ListOptions{})
        if err != nil {
            return err
        }

        if len(netpols.Items) == 0 {
            report.AddFinding(reporter.Finding{
                Module:    "netpol",
                Namespace: ns.Name,
                Resource:  "namespace",
                RiskLevel: "high",
                Message:   "No NetworkPolicy defined; all pods can communicate freely",
            })
            continue
        }

        for _, np := range netpols.Items {
            if allowsAllTraffic(np) {
                report.AddFinding(reporter.Finding{
                    Module:    "netpol",
                    Namespace: ns.Name,
                    Resource:  np.Name,
                    RiskLevel: "medium",
                    Message:   "NetworkPolicy allows unrestricted ingress or egress traffic",
                })
            }
        }
    }

    return nil
}

func allowsAllTraffic(np networkingv1.NetworkPolicy) bool {
    return len(np.Spec.Ingress) == 0 && len(np.Spec.Egress) == 0 && np.Spec.PolicyTypes != nil
}

namespace PCPlus.Core.Interfaces
{
    /// <summary>
    /// AI analysis interface. Modules can use this for intelligent analysis.
    /// Implementations can use local ML models, cloud APIs (OpenAI/Claude), or both.
    /// This is the integration point Paul requested for future AI capabilities.
    /// </summary>
    public interface IAiAnalyzer
    {
        /// <summary>Whether AI analysis is available and configured.</summary>
        bool IsAvailable { get; }

        /// <summary>
        /// Analyze a security event and return threat assessment.
        /// Used by ransomware module to evaluate suspicious behavior.
        /// </summary>
        Task<ThreatAssessment> AnalyzeThreatAsync(ThreatContext context);

        /// <summary>
        /// Analyze system health patterns and return recommendations.
        /// Used by health module for predictive maintenance.
        /// </summary>
        Task<HealthRecommendation> AnalyzeHealthAsync(HealthAnalysisContext context);

        /// <summary>
        /// Classify a process as legitimate, suspicious, or malicious.
        /// Used by ransomware module for process behavior analysis.
        /// </summary>
        Task<ProcessClassification> ClassifyProcessAsync(ProcessAnalysisContext context);

        /// <summary>
        /// Generate a human-readable summary of system state.
        /// Used for monthly report cards and dashboard summaries.
        /// </summary>
        Task<string> GenerateSummaryAsync(SystemSummaryContext context);
    }

    public class ThreatContext
    {
        public string ProcessName { get; set; } = "";
        public string ProcessPath { get; set; } = "";
        public int ProcessId { get; set; }
        public string[] FileOperations { get; set; } = Array.Empty<string>();
        public string[] NetworkConnections { get; set; } = Array.Empty<string>();
        public string[] RegistryChanges { get; set; } = Array.Empty<string>();
        public string[] CommandLineArgs { get; set; } = Array.Empty<string>();
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class ThreatAssessment
    {
        public float ThreatScore { get; set; } // 0.0 - 1.0
        public string Classification { get; set; } = ""; // benign, suspicious, malicious
        public string Reasoning { get; set; } = "";
        public string[] RecommendedActions { get; set; } = Array.Empty<string>();
        public float Confidence { get; set; } // 0.0 - 1.0
    }

    public class HealthAnalysisContext
    {
        public float[] CpuHistory { get; set; } = Array.Empty<float>();
        public float[] RamHistory { get; set; } = Array.Empty<float>();
        public float[] TempHistory { get; set; } = Array.Empty<float>();
        public float[] DiskUsageHistory { get; set; } = Array.Empty<float>();
        public string[] RecentAlerts { get; set; } = Array.Empty<string>();
        public Dictionary<string, object> SystemInfo { get; set; } = new();
    }

    public class HealthRecommendation
    {
        public string Summary { get; set; } = "";
        public string[] Recommendations { get; set; } = Array.Empty<string>();
        public string[] PredictedIssues { get; set; } = Array.Empty<string>();
        public float OverallHealthScore { get; set; }
    }

    public class ProcessAnalysisContext
    {
        public string ProcessName { get; set; } = "";
        public string ProcessPath { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public string Publisher { get; set; } = "";
        public bool IsSigned { get; set; }
        public float CpuUsage { get; set; }
        public float MemoryMB { get; set; }
        public string[] NetworkActivity { get; set; } = Array.Empty<string>();
        public string[] FileActivity { get; set; } = Array.Empty<string>();
    }

    public class ProcessClassification
    {
        public string Classification { get; set; } = ""; // legitimate, suspicious, malicious
        public float Confidence { get; set; }
        public string Reasoning { get; set; } = "";
        public bool ShouldBlock { get; set; }
    }

    public class SystemSummaryContext
    {
        public Dictionary<string, object> HealthData { get; set; } = new();
        public Dictionary<string, object> SecurityData { get; set; } = new();
        public string[] RecentAlerts { get; set; } = Array.Empty<string>();
        public string[] RecentActions { get; set; } = Array.Empty<string>();
        public TimeSpan Period { get; set; } = TimeSpan.FromDays(30);
    }
}

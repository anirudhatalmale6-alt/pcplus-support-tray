namespace PCPlus.Core.Models
{
    /// <summary>Point-in-time snapshot of system health.</summary>
    public class HealthSnapshot
    {
        public float CpuPercent { get; set; }
        public float RamPercent { get; set; }
        public float RamUsedGB { get; set; }
        public float RamTotalGB { get; set; }
        public List<DiskReading> Disks { get; set; } = new();
        public float CpuTempC { get; set; }
        public float GpuTempC { get; set; }
        public string CpuTempSource { get; set; } = "";
        public string GpuTempSource { get; set; } = "";
        public float NetworkSentKBps { get; set; }
        public float NetworkRecvKBps { get; set; }
        public TimeSpan Uptime { get; set; }
        public int ProcessCount { get; set; }
        public List<ProcessReading> TopProcesses { get; set; } = new();
        public SmartHealth? DiskSmart { get; set; }
        public StartupPerformance? StartupPerf { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class DiskReading
    {
        public string Name { get; set; } = "";
        public string Label { get; set; } = "";
        public float TotalGB { get; set; }
        public float FreeGB { get; set; }
        public float UsedPercent { get; set; }
    }

    public class ProcessReading
    {
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public float CpuPercent { get; set; }
        public float MemoryMB { get; set; }
        public int Pid { get; set; }
        public bool IsSigned { get; set; }
        public string Publisher { get; set; } = "";
    }

    public class SmartHealth
    {
        public List<DiskSmartInfo> Drives { get; set; } = new();
    }

    public class DiskSmartInfo
    {
        public string DeviceName { get; set; } = "";
        public string Model { get; set; } = "";
        public string Serial { get; set; } = "";
        public string Status { get; set; } = ""; // OK, Caution, Bad
        public int TemperatureC { get; set; }
        public int PowerOnHours { get; set; }
        public int ReallocatedSectors { get; set; }
        public int PendingSectors { get; set; }
    }

    public class StartupPerformance
    {
        public double BootTimeSeconds { get; set; }
        public int StartupProgramCount { get; set; }
        public List<StartupItem> SlowStartupItems { get; set; } = new();
    }

    public class StartupItem
    {
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public double ImpactMs { get; set; }
        public bool Enabled { get; set; }
    }
}

namespace PCPlus.Core.Models
{
    public class DnsStatsDto
    {
        public string ClientIp { get; set; } = "";
        public bool HasClientData { get; set; }
        public int ClientTotalQueries { get; set; }
        public int ClientBlockedQueries { get; set; }
        public List<DnsStatDomainDto> ClientTopBlocked { get; set; } = new();
        public List<DnsStatDomainDto> ClientTopQueried { get; set; } = new();
        public string LastBlockedDomain { get; set; } = "";
        public long GlobalTotalQueries { get; set; }
        public long GlobalBlockedQueries { get; set; }
        public long FilterListCount { get; set; }
        public List<DnsStatDomainDto> GlobalTopBlocked { get; set; } = new();
        public DateTime FetchedAt { get; set; }
        public string? Error { get; set; }

        public double ClientBlockRate => ClientTotalQueries > 0
            ? Math.Round((double)ClientBlockedQueries / ClientTotalQueries * 100, 1) : 0;
    }

    public class DnsStatDomainDto
    {
        public string Domain { get; set; } = "";
        public int Count { get; set; }
    }
}

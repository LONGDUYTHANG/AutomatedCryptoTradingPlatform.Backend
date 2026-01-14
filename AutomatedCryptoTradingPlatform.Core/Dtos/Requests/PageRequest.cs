using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests
{
    /// <summary>
    /// DTO chứa các tham số để lọc, tìm kiếm và phân trang
    /// </summary>
    public class PageRequest
    {
        /// <summary>
        /// Số trang (bắt đầu từ 1)
        /// </summary>
        public int PageNumber { get; set; } = 1;

        /// <summary>
        /// Số bản ghi trên mỗi trang
        /// </summary>
        public int PageSize { get; set; }

        /// <summary>
        /// Từ khóa tìm kiếm
        /// </summary>
        public string? SearchTerm { get; set; }

        /// <summary>
        /// Tên cột cần sắp xếp
        /// </summary>
        public string? SortBy { get; set; }

        /// <summary>
        /// Hướng sắp xếp: "ASC" hoặc "DESC"
        /// </summary>
        public string SortDirection { get; set; } = "ASC";

        /// <summary>
        /// Các bộ lọc bổ sung (tùy chỉnh theo nghiệp vụ)
        /// </summary>
        public Dictionary<string, object>? Filters { get; set; }
    }
}

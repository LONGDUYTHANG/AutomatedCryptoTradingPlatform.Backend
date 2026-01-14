using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses
{
    /// <summary>
    /// DTO trả về kết quả phân trang
    /// </summary>
    public class PagedResult<T>
    {
        /// <summary>
        /// Dữ liệu phân trang
        /// </summary>
        public List<T> Data { get; set; }
        /// <summary>
        /// Số trang hiện tại
        /// </summary>
        public int CurrentPage { get; set; }
        /// <summary>
        /// Kích thước trang
        /// </summary>
        public int PageSize { get; set; }
        /// <summary>
        /// Tổng số trang
        /// </summary>
        public int TotalPages { get; set; }
        /// <summary>
        /// Tổng số bản ghi
        /// </summary>
        public int TotalRecords { get; set; }
        /// <summary>
        /// Có trang trước?
        /// </summary>
        public bool HasPreviousPage => CurrentPage > 1;
        /// <summary>
        /// Có trang sau?
        /// </summary>
        public bool HasNextPage => CurrentPage < TotalPages;
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses
{
    /// <summary>
    /// Base Response trả về trong mọi trường hợp call API 
    /// </summary>
    public class BaseResponse<T>
    {
        /// <summary>
        /// Code trạng thái response
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        /// Trạng thái response (true là response trả về thành công, false là fail)
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Message đính kèm theo response
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// Đây là dữ liệu 
        /// </summary>
        public T? Data { get; set; }

        /// <summary>
        /// Lỗi validate server side nếu có, tất cả đều trả qua property này
        /// Example một validation trả về
        /// {
        ///     "PhoneNumber": [
        ///         "PhoneNumber is required",
        ///         "PhoneNumber must >= 10 digits"
        ///     ]
        /// }
        /// </summary>
        public IDictionary<string, string[]>? ValidationErrors { get; set; }

        /// <summary>
        /// Constructor không tham số
        /// </summary>
        public BaseResponse()
        {
            
        }

        /// <summary>
        /// Constructor khởi tạo một base response cơ bản
        /// </summary>
        /// <param name="data"></param>
        /// <param name="message"></param>
        public BaseResponse(T data, string message)
        {
            Data = data;
            Message = message;
        }
    }
}

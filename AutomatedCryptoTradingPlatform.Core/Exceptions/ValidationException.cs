using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AutomatedCryptoTradingPlatform.Core.Exceptions
{
    public class ValidationException : Exception
    {
        /// <summary>
        /// Property chứa lỗi truyền từ ngoài
        /// </summary>
        public IDictionary<string, string[]> Errors { get; set; }

        /// <summary>
        /// Constructor khởi tạo một validation exception cơ bản
        /// </summary>
        /// <param name="errors"></param>
        public ValidationException(IDictionary<string, string[]> errors) : base("Có lỗi Validation") 
        {
            Errors = errors;
        }
    }
}

using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Repositories
{
    /// <summary>
    /// Base Repository
    /// </summary>
    public interface IBaseRepository<T>
    {
        //Lấy toàn bộ data
        List<T> GetAll();
        //Lấy data theo Id
        T GetById(Guid entityId);
        //Insert data
        T Insert(T entity);
        //Xóa data
        void Delete(Guid entityId);
        //Update data
        T Update(T entity);
        //Lấy data phân trang
        PagedResult<T> GetPaged(int pageNumber, int pageSize, string? searchTerm, Dictionary<string, object>? filters, string? sortBy, string? sortDirection = "ASC");
    }
}

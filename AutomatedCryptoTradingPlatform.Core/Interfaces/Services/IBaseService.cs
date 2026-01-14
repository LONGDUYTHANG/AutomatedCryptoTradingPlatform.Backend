using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services
{
    public interface IBaseService<T>
    {
        /// <summary>
        /// Các method CRUD cơ bản
        /// </summary>
        /// <returns></returns>
        List<T> GetAll();
        T GetById(Guid entityId);
        T Insert(T entity);
        void Delete(Guid entityId);
        T Update(T entity);
        PagedResult<T> GetPaged(int pageNumber, int pageSize, string? searchTerm, Dictionary<string, object>? filters, string? sortBy, string? sortDirection = "ASC");

        /// <summary>
        /// Method để validate
        /// </summary>
        /// <param name="entity"></param>
        /// <param name="isUpdate"></param>
        void Validate(T entity, bool isUpdate);
    }
}

using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Repositories;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using System;
using System.Collections.Generic;

namespace AutomatedCryptoTradingPlatform.Core.Services
{
    /// <summary>
    /// Base service cung cấp các nghiệp vụ cơ bản và validate cho các entity
    /// </summary>
    /// <typeparam name="T">Kiểu entity của business object</typeparam>
    /// Created by: LDthang - 4/12/2025
    /// Updated by: LDthang - 14/1/2026
    public class BaseService<T> : IBaseService<T> where T : class
    {
        protected readonly IBaseRepository<T> _repository;

        /// <summary>
        /// Khởi tạo base service với repository tương ứng
        /// </summary>
        /// <param name="repository">Repository để thao tác với database</param>
        /// Created by: LDthang - 4/12/2025
        public BaseService(IBaseRepository<T> repository)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        }

        /// <summary>
        /// Lấy tất cả bản ghi
        /// </summary>
        /// <returns>Danh sách tất cả các bản ghi</returns>
        /// Created by: LDthang - 4/12/2025
        public virtual List<T> GetAll()
        {
            try
            {
                return _repository.GetAll();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to get all {typeof(T).Name} records", ex);
            }
        }

        /// <summary>
        /// Lấy một bản ghi theo ID
        /// </summary>
        /// <param name="entityId">ID của bản ghi cần lấy</param>
        /// <returns>Đối tượng entity tìm được hoặc null nếu không tìm thấy</returns>
        /// Created by: LDthang - 4/12/2025
        public virtual T GetById(Guid entityId)
        {
            try
            {
                if (entityId == Guid.Empty)
                    throw new ArgumentException("Entity ID cannot be empty", nameof(entityId));

                return _repository.GetById(entityId);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to get {typeof(T).Name} with ID {entityId}", ex);
            }
        }

        /// <summary>
        /// Thêm mới một bản ghi sau khi validate dữ liệu
        /// </summary>
        /// <param name="entity">Đối tượng entity cần thêm mới</param>
        /// <returns>Đối tượng entity vừa được thêm</returns>
        /// Created by: LDthang - 4/12/2025
        public virtual T Insert(T entity)
        {
            try
            {
                if (entity == null)
                    throw new ArgumentNullException(nameof(entity), "Entity cannot be null");

                // Validate dữ liệu trước khi insert
                Validate(entity, isUpdate: false);

                return _repository.Insert(entity);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to insert {typeof(T).Name}", ex);
            }
        }

        /// <summary>
        /// Cập nhật một bản ghi sau khi validate dữ liệu
        /// </summary>
        /// <param name="entity">Đối tượng entity chứa dữ liệu cần cập nhật</param>
        /// <returns>Đối tượng entity sau khi cập nhật</returns>
        /// Created by: LDthang - 4/12/2025
        public virtual T Update(T entity)
        {
            try
            {
                if (entity == null)
                    throw new ArgumentNullException(nameof(entity), "Entity cannot be null");

                // Validate dữ liệu trước khi update
                Validate(entity, isUpdate: true);

                return _repository.Update(entity);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to update {typeof(T).Name}", ex);
            }
        }

        /// <summary>
        /// Xóa một bản ghi theo ID
        /// </summary>
        /// <param name="entityId">ID của bản ghi cần xóa</param>
        /// Created by: LDthang - 4/12/2025
        public virtual void Delete(Guid entityId)
        {
            try
            {
                if (entityId == Guid.Empty)
                    throw new ArgumentException("Entity ID cannot be empty", nameof(entityId));

                // Kiểm tra bản ghi có tồn tại không
                var existingEntity = _repository.GetById(entityId);
                if (existingEntity == null)
                    throw new KeyNotFoundException($"{typeof(T).Name} with ID {entityId} not found");

                _repository.Delete(entityId);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to delete {typeof(T).Name} with ID {entityId}", ex);
            }
        }

        /// <summary>
        /// Lấy dữ liệu có phân trang, tìm kiếm, lọc và sắp xếp
        /// </summary>
        /// <param name="pageNumber">Số trang (bắt đầu từ 1)</param>
        /// <param name="pageSize">Số bản ghi trên mỗi trang</param>
        /// <param name="searchTerm">Từ khóa tìm kiếm (tìm trong tất cả các cột string)</param>
        /// <param name="filters">Dictionary chứa các điều kiện lọc (key: tên cột, value: giá trị)</param>
        /// <param name="sortBy">Tên cột cần sắp xếp</param>
        /// <param name="sortDirection">Hướng sắp xếp: "ASC" hoặc "DESC"</param>
        /// <returns>PagedResult chứa dữ liệu và thông tin phân trang</returns>
        /// Created by: LDthang - 5/12/2025
        public virtual PagedResult<T> GetPaged(
            int pageNumber,
            int pageSize,
            string? searchTerm = null,
            Dictionary<string, object>? filters = null,
            string? sortBy = null,
            string? sortDirection = "ASC")
        {
            try
            {
                if (pageNumber < 1)
                    throw new ArgumentException("Page number must be greater than 0", nameof(pageNumber));

                if (pageSize < 1)
                    throw new ArgumentException("Page size must be greater than 0", nameof(pageSize));

                if (pageSize > 1000)
                    throw new ArgumentException("Page size cannot exceed 1000", nameof(pageSize));

                return _repository.GetPaged(pageNumber, pageSize, searchTerm, filters, sortBy, sortDirection);
            }
            catch (ArgumentException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to get paged {typeof(T).Name} records", ex);
            }
        }

        /// <summary>
        /// Validate dữ liệu của entity
        /// Override method này trong các service con để thực hiện validation cụ thể
        /// </summary>
        /// <param name="entity">Đối tượng entity cần validate</param>
        /// <param name="isUpdate">Trạng thái Add hay Update</param>
        /// Created by: LDthang - 4/12/2025
        public virtual void Validate(T entity, bool isUpdate)
        {
            // Base implementation - không làm gì
            // Các service con sẽ override method này để thực hiện validation cụ thể
        }
    }
}
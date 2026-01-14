using AutomatedCryptoTradingPlatform.Core.Attributes;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Repositories;
using Dapper;
using Humanizer;
using Microsoft.Extensions.Configuration;
using MySqlConnector;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories
{
    /// <summary>
    /// Base repository cung cấp các thao tác CRUD cơ bản và phân trang cho các entity
    /// </summary>
    /// <typeparam name="T">Kiểu entity của bảng trong database</typeparam>
    /// Created by: LDthang - 4/12/2025
    /// Updated by: LDthang - 14/1/2026
    public class BaseRepository<T> : IBaseRepository<T>, IDisposable where T : class
    {
        protected readonly string _connectionString;
        protected readonly IDbConnection _dbConnection;
        private readonly string _tableName;
        private readonly PropertyInfo[] _properties;
        private readonly PropertyInfo _keyProperty;
        private readonly string _keyName;

        /// <summary>
        /// Khởi tạo repository và kết nối đến database
        /// </summary>
        /// <param name="config">Configuration để lấy connection string</param>
        /// Created by: LDthang - 4/12/2025
        public BaseRepository(IConfiguration config)
        {
            try
            {
                _connectionString = config.GetConnectionString("MyCnn")
                    ?? throw new InvalidOperationException("Connection string 'MyCnn' not found in configuration");

                _dbConnection = new MySqlConnection(_connectionString);
                _tableName = typeof(T).Name.Underscore();
                _properties = typeof(T).GetProperties();

                // Cache key property để tránh phải tìm lại nhiều lần
                _keyProperty = _properties.FirstOrDefault(p => Attribute.IsDefined(p, typeof(TrackProperty)))
                    ?? throw new InvalidOperationException($"No key property with TrackProperty attribute found in {typeof(T).Name}");

                _keyName = _keyProperty.Name.Underscore();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to initialize BaseRepository for {typeof(T).Name}", ex);
            }
        }

        /// <summary>
        /// Lấy toàn bộ dữ liệu của một bảng từ database
        /// </summary>
        /// <returns>Danh sách tất cả các bản ghi</returns>
        /// Created by: LDthang - 4/12/2025
        public List<T> GetAll()
        {
            try
            {
                var sqlCommand = $"SELECT * FROM {_tableName}";
                return _dbConnection.Query<T>(sqlCommand).AsList();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to get all records from {_tableName}", ex);
            }
        }

        /// <summary>
        /// Lấy dữ liệu của một bản ghi trong bảng từ database theo ID
        /// </summary>
        /// <param name="id">ID của bản ghi cần lấy</param>
        /// <returns>Đối tượng entity tìm được hoặc null nếu không tìm thấy</returns>
        /// Created by: LDthang - 4/12/2025
        public T GetById(Guid id)
        {
            try
            {
                var sqlCommand = $"SELECT * FROM {_tableName} WHERE {_keyName} = @Id";
                return _dbConnection.QueryFirstOrDefault<T>(sqlCommand, new { Id = id });
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to get record with ID {id} from {_tableName}", ex);
            }
        }

        /// <summary>
        /// Thêm mới một bản ghi vào bảng trong database
        /// </summary>
        /// <param name="entity">Đối tượng entity cần thêm mới</param>
        /// <returns>Đối tượng entity vừa được thêm</returns>
        /// Created by: LDthang - 4/12/2025
        public virtual T Insert(T entity)
        {
            try
            {
                var columns = new StringBuilder();
                var columnParams = new StringBuilder();
                var parameters = new DynamicParameters();

                foreach (var prop in _properties)
                {
                    var snakeCaseProp = prop.Name.Underscore();

                    if (columns.Length > 0)
                    {
                        columns.Append(',');
                        columnParams.Append(',');
                    }

                    columns.Append(snakeCaseProp);
                    columnParams.Append($"@{snakeCaseProp}");
                    parameters.Add($"@{snakeCaseProp}", prop.GetValue(entity));
                }

                var sql = $"INSERT INTO {_tableName}({columns}) VALUES ({columnParams})";
                _dbConnection.Execute(sql, parameters);

                return entity;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to insert record into {_tableName}", ex);
            }
        }

        /// <summary>
        /// Cập nhật dữ liệu của một bản ghi trong bảng
        /// </summary>
        /// <param name="entity">Đối tượng entity chứa dữ liệu cần cập nhật</param>
        /// <returns>Đối tượng entity sau khi cập nhật</returns>
        /// Created by: LDthang - 4/12/2025
        public virtual T Update(T entity)
        {
            try
            {
                var setClause = new StringBuilder();
                var parameters = new DynamicParameters();

                foreach (var prop in _properties)
                {
                    var snakeCaseProp = prop.Name.Underscore();

                    if (snakeCaseProp.Equals(_keyName, StringComparison.OrdinalIgnoreCase))
                    {
                        parameters.Add("@Id", prop.GetValue(entity));
                        continue;
                    }

                    if (setClause.Length > 0)
                        setClause.Append(',');

                    setClause.Append($"{snakeCaseProp} = @{snakeCaseProp}");
                    parameters.Add($"@{snakeCaseProp}", prop.GetValue(entity));
                }

                var sql = $"UPDATE {_tableName} SET {setClause} WHERE {_keyName} = @Id";
                _dbConnection.Execute(sql, parameters);

                return entity;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to update record in {_tableName}", ex);
            }
        }

        /// <summary>
        /// Xóa một bản ghi khỏi bảng trong database
        /// </summary>
        /// <param name="id">ID của bản ghi cần xóa</param>
        /// Created by: LDthang - 4/12/2025
        public virtual void Delete(Guid id)
        {
            try
            {
                var sql = $"DELETE FROM {_tableName} WHERE {_keyName} = @Id";
                _dbConnection.Execute(sql, new { Id = id });
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to delete record with ID {id} from {_tableName}", ex);
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
        public PagedResult<T> GetPaged(
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

                var parameters = new DynamicParameters();
                var whereConditions = new List<string>();

                // Xây dựng điều kiện tìm kiếm
                BuildSearchConditions(searchTerm, whereConditions, parameters);

                // Xây dựng điều kiện lọc
                BuildFilterConditions(filters, whereConditions, parameters);

                // Tạo câu WHERE
                var whereClause = whereConditions.Any()
                    ? "WHERE " + string.Join(" AND ", whereConditions)
                    : string.Empty;

                // Xử lý sắp xếp
                var orderByClause = BuildOrderByClause(sortBy, sortDirection);

                // Tính toán offset
                var offset = (pageNumber - 1) * pageSize;
                parameters.Add("@Offset", offset);
                parameters.Add("@PageSize", pageSize);

                // Query lấy tổng số bản ghi
                var countSql = $"SELECT COUNT(*) FROM {_tableName} {whereClause}";
                var totalRecords = _dbConnection.QuerySingle<int>(countSql, parameters);

                // Query lấy dữ liệu phân trang
                var dataSql = $@"
                    SELECT * FROM {_tableName}
                    {whereClause}
                    {orderByClause}
                    LIMIT @PageSize OFFSET @Offset";

                var data = _dbConnection.Query<T>(dataSql, parameters).AsList();

                // Tạo kết quả
                return new PagedResult<T>
                {
                    Data = data,
                    CurrentPage = pageNumber,
                    PageSize = pageSize,
                    TotalRecords = totalRecords,
                    TotalPages = (int)Math.Ceiling(totalRecords / (double)pageSize)
                };
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to get paged records from {_tableName}", ex);
            }
        }

        /// <summary>
        /// Xây dựng điều kiện tìm kiếm
        /// </summary>
        private void BuildSearchConditions(string? searchTerm, List<string> whereConditions, DynamicParameters parameters)
        {
            if (string.IsNullOrWhiteSpace(searchTerm))
                return;

            var stringProperties = _properties
                .Where(p => p.PropertyType == typeof(string))
                .Select(p => p.Name.Underscore())
                .ToList();

            if (stringProperties.Any())
            {
                var searchConditions = stringProperties.Select(col => $"{col} LIKE @SearchTerm");
                whereConditions.Add($"({string.Join(" OR ", searchConditions)})");
                parameters.Add("@SearchTerm", $"%{searchTerm}%");
            }
        }

        /// <summary>
        /// Xây dựng điều kiện lọc
        /// </summary>
        private void BuildFilterConditions(Dictionary<string, object>? filters, List<string> whereConditions, DynamicParameters parameters)
        {
            if (filters == null || !filters.Any())
                return;

            foreach (var filter in filters)
            {
                var columnName = filter.Key.Underscore();

                if (filter.Value == null)
                {
                    whereConditions.Add($"{columnName} IS NULL");
                }
                else
                {
                    var paramName = $"@Filter_{filter.Key}";
                    var actualValue = ConvertFilterValue(filter.Value);

                    whereConditions.Add($"{columnName} = {paramName}");
                    parameters.Add(paramName, actualValue);
                }
            }
        }

        /// <summary>
        /// Xây dựng ORDER BY clause
        /// </summary>
        private string BuildOrderByClause(string? sortBy, string? sortDirection)
        {
            if (string.IsNullOrWhiteSpace(sortBy))
                return string.Empty;

            var sortColumn = sortBy.Underscore();
            var direction = string.Equals(sortDirection, "DESC", StringComparison.OrdinalIgnoreCase)
                ? "DESC"
                : "ASC";

            return $"ORDER BY {sortColumn} {direction}";
        }

        /// <summary>
        /// Chuyển đổi giá trị filter từ JsonElement sang kiểu dữ liệu thực
        /// </summary>
        protected object ConvertFilterValue(object value)
        {
            if (value == null)
                return null;

            if (value is JsonElement jsonElement)
            {
                return jsonElement.ValueKind switch
                {
                    JsonValueKind.String => jsonElement.GetString(),
                    JsonValueKind.Number => jsonElement.TryGetInt32(out int intVal)
                        ? intVal
                        : (object)jsonElement.GetDecimal(),
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.Null => null,
                    _ => jsonElement.ToString()
                };
            }

            return value;
        }

        /// <summary>
        /// Giải phóng kết nối database sau khi sử dụng
        /// </summary>
        /// Created by: LDthang - 4/12/2025
        public void Dispose()
        {
            _dbConnection?.Dispose();
        }
    }
}
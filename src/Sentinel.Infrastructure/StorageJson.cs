using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Infrastructure;

internal static class StorageJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 128
    };
}

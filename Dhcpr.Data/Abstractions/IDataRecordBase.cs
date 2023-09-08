namespace Dhcpr.Data.Abstractions;

internal interface IDataRecordBase
{
    string Id { get; set; }
    DateTimeOffset Created { get; set; }
    DateTimeOffset Modified { get; set; }
}
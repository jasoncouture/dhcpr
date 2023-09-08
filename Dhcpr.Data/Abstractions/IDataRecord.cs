namespace Dhcpr.Data.Abstractions;

internal interface IDataRecord<T> : ISelfBuildingModel<T> where T : class, IDataRecord<T>
{
    string Id { get; set; }
    DateTimeOffset Created { get; set; }
    DateTimeOffset Modified { get; set; }
}
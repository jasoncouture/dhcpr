namespace Dhcpr.Data.Abstractions;

internal interface IDataRecord<T> : IDataRecordBase, ISelfBuildingModel<T> where T : class, IDataRecord<T>
{

}
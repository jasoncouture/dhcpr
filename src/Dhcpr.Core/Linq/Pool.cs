namespace Dhcpr.Core.Linq;

public static class Pool
{
    public static PooledHashSet<T> GetHashSet<T>() => HashSetPool<T>.Default.Get();
    public static PooledList<T> GetList<T>() => ListPool<T>.Default.Get();

    public static void Return<T>(PooledHashSet<T> set) => HashSetPool<T>.Default.Return(set);
    public static void Return<T>(PooledList<T> set) => ListPool<T>.Default.Return(set);
}
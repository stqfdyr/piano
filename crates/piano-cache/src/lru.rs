//! A store bounded by the total weight of its entries, evicting the least recently used.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// What an entry costs besides its key text and its value: the key in both tables, the
/// use counter in both, and the shared key's reference counts.
pub const ENTRY: usize = 2 * size_of::<Arc<str>>() + 2 * size_of::<u64>() + 2 * size_of::<usize>();

/// The bytes a value holds, for the store's bound. The store adds the key's.
pub trait Weigh {
    fn weight(&self) -> usize;
}

impl<T: Weigh> Weigh for Arc<T> {
    fn weight(&self) -> usize {
        T::weight(self)
    }
}

#[derive(Debug)]
pub struct Lru<V> {
    capacity: usize,
    used: usize,
    tick: u64,
    map: HashMap<Arc<str>, (u64, V)>,
    order: BTreeMap<u64, Arc<str>>,
}

impl<V: Weigh> Lru<V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            used: 0,
            tick: 0,
            map: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Total weight of the entries: values, keys and bookkeeping. Keys come from
    /// requests, so they count; otherwise long keys with light values would outgrow the
    /// bound many times over.
    pub fn used(&self) -> usize {
        self.used
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The value for `key`, now the most recently used.
    pub fn get(&mut self, key: &str) -> Option<&V> {
        self.tick += 1;
        let tick = self.tick;
        let (seq, v) = self.map.get_mut(key)?;
        if let Some(k) = self.order.remove(seq) {
            self.order.insert(tick, k);
        }
        *seq = tick;
        Some(v)
    }

    /// Stores `value`, evicting the least recently used entries beyond the capacity. An
    /// entry heavier than the whole capacity is not stored.
    pub fn insert(&mut self, key: String, value: V) {
        self.remove(&key);
        let w = cost(&key, &value);
        if w > self.capacity {
            return;
        }
        self.tick += 1;
        self.used += w;
        let key: Arc<str> = key.into();
        self.order.insert(self.tick, Arc::clone(&key));
        self.map.insert(key, (self.tick, value));
        self.evict();
    }

    pub fn remove(&mut self, key: &str) -> Option<V> {
        let (k, (seq, v)) = self.map.remove_entry(key)?;
        self.order.remove(&seq);
        self.used -= cost(&k, &v);
        Some(v)
    }

    /// Removes everything; returns how many values there were.
    pub fn clear(&mut self) -> usize {
        let n = self.map.len();
        self.map.clear();
        self.order.clear();
        self.used = 0;
        n
    }

    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        self.evict();
    }

    fn evict(&mut self) {
        while self.used > self.capacity {
            let Some((_, key)) = self.order.pop_first() else {
                break;
            };
            if let Some((_, v)) = self.map.remove(&key) {
                self.used -= cost(&key, &v);
            }
        }
    }
}

fn cost<V: Weigh>(key: &str, value: &V) -> usize {
    key.len() + ENTRY + value.weight()
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Weigh for usize {
        fn weight(&self) -> usize {
            *self
        }
    }

    /// The weight of an entry with a one-byte key and a value of weight `w`.
    fn one(w: usize) -> usize {
        1 + ENTRY + w
    }

    #[test]
    fn evicts_least_recently_used_by_weight() {
        let mut l = Lru::new(one(4) * 2 + 1);
        l.insert("a".into(), 4usize);
        l.insert("b".into(), 4);
        assert_eq!(l.get("a"), Some(&4));
        l.insert("c".into(), 4);
        assert!(l.get("b").is_none(), "b was least recently used");
        assert_eq!(l.used(), one(4) * 2);
        assert_eq!(l.len(), 2);
        assert!(!l.is_empty());
        l.insert("big".into(), l.capacity());
        assert!(l.get("big").is_none());
        assert_eq!(l.used(), one(4) * 2);
    }

    #[test]
    fn replace_remove_clear_and_shrink() {
        let mut l = Lru::new(one(3) * 2);
        l.insert("a".into(), 3usize);
        l.insert("a".into(), 5);
        assert_eq!(l.used(), one(5));
        assert_eq!(l.remove("a"), Some(5));
        assert_eq!(l.used(), 0);
        l.insert("a".into(), 3);
        l.insert("b".into(), 3);
        assert_eq!(l.len(), 2);
        l.set_capacity(one(3));
        assert_eq!(l.len(), 1);
        assert!(l.get("b").is_some());
        assert_eq!(l.clear(), 1);
        assert!(l.is_empty());
        assert_eq!(l.used(), 0);
        l.set_capacity(0);
        l.insert("z".into(), 0);
        assert!(l.is_empty(), "every entry weighs something");
    }

    #[test]
    fn keys_count_toward_the_bound() {
        let key = |i: usize| format!("{i:04}{}", "k".repeat(996));
        let mut l = Lru::new(10 * (1000 + ENTRY));
        for i in 0..100 {
            l.insert(key(i), 0usize);
        }
        assert_eq!(
            l.len(),
            10,
            "weightless values with long keys still fill the store"
        );
        assert_eq!(l.used(), 10 * (1000 + ENTRY));
        assert!(l.get(&key(99)).is_some());
        assert!(l.get(&key(89)).is_none());
        l.remove(&key(99));
        assert_eq!(l.used(), 9 * (1000 + ENTRY));
    }

    #[test]
    fn shared_values_weigh_what_they_hold() {
        let mut l = Lru::new(100);
        l.insert("a".into(), Arc::new(6usize));
        assert_eq!(l.used(), one(6));
    }
}

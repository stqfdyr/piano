//! A store bounded by the total weight of its values, evicting the least recently used.

use std::collections::{BTreeMap, HashMap};

/// The bytes a value holds, for the store's bound.
pub trait Weigh {
    fn weight(&self) -> usize;
}

impl<T: Weigh> Weigh for std::sync::Arc<T> {
    fn weight(&self) -> usize {
        T::weight(self)
    }
}

#[derive(Debug)]
pub struct Lru<V> {
    capacity: usize,
    used: usize,
    tick: u64,
    map: HashMap<String, (u64, V)>,
    order: BTreeMap<u64, String>,
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

    /// Total weight of the stored values.
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

    /// Stores `value`, evicting the least recently used values beyond the capacity. A
    /// value heavier than the whole capacity is not stored.
    pub fn insert(&mut self, key: String, value: V) {
        self.remove(&key);
        let w = value.weight();
        if w > self.capacity {
            return;
        }
        self.tick += 1;
        self.used += w;
        self.order.insert(self.tick, key.clone());
        self.map.insert(key, (self.tick, value));
        self.evict();
    }

    pub fn remove(&mut self, key: &str) -> Option<V> {
        let (seq, v) = self.map.remove(key)?;
        self.order.remove(&seq);
        self.used -= v.weight();
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
                self.used -= v.weight();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Weigh for usize {
        fn weight(&self) -> usize {
            *self
        }
    }

    #[test]
    fn evicts_least_recently_used_by_weight() {
        let mut l = Lru::new(10);
        assert_eq!(l.capacity(), 10);
        l.insert("a".into(), 4usize);
        l.insert("b".into(), 4);
        assert_eq!(l.get("a"), Some(&4));
        l.insert("c".into(), 4);
        assert!(l.get("b").is_none(), "b was least recently used");
        assert_eq!(l.used(), 8);
        assert_eq!(l.len(), 2);
        assert!(!l.is_empty());
        l.insert("big".into(), 11);
        assert!(l.get("big").is_none());
        assert_eq!(l.used(), 8);
    }

    #[test]
    fn replace_remove_clear_and_shrink() {
        let mut l = Lru::new(10);
        l.insert("a".into(), 3usize);
        l.insert("a".into(), 5);
        assert_eq!(l.used(), 5);
        assert_eq!(l.remove("a"), Some(5));
        assert_eq!(l.used(), 0);
        l.insert("a".into(), 3);
        l.insert("b".into(), 3);
        l.set_capacity(4);
        assert_eq!(l.len(), 1);
        assert!(l.get("b").is_some());
        assert_eq!(l.clear(), 1);
        assert!(l.is_empty());
        l.set_capacity(0);
        l.insert("z".into(), 0);
        assert_eq!(l.len(), 1, "weightless values fit a zero capacity");
    }

    #[test]
    fn shared_values_weigh_what_they_hold() {
        let mut l = Lru::new(10);
        l.insert("a".into(), std::sync::Arc::new(6usize));
        assert_eq!(l.used(), 6);
    }
}

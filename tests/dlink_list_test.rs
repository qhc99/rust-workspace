use rust_libs::dlink_list::DLinkList;

#[test]
// ---Drop dlink list---
// Drop val RefCell { value: 6 }.
// Drop val RefCell { value: 5 }.
// Drop val RefCell { value: 4 }.
// Drop val RefCell { value: 1 }.
// Drop val RefCell { value: 2 }.
// Drop val RefCell { value: 3 }.
// Drop head or tail.
// Drop head or tail.
fn dlink_list_drop_insert_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    assert_eq!(3, l.len());

    l.insert_last(4);
    l.insert_last(5);
    l.insert_last(6);

    assert_eq!(6, l.len());
}

#[test]
// Drop val RefCell { value: 1 }.
// Drop val RefCell { value: 2 }.
// Drop val RefCell { value: 3 }.
// ---Drop dlink list---
// Drop head or tail.
// Drop head or tail.
fn dlink_list_drop_remove_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    assert_eq!(3, l.len());

    l.remove_last();
    l.remove_last();
    l.remove_last();

    assert_eq!(0, l.len());
}

#[test]
// Drop val RefCell { value: 3 }.
// Drop val RefCell { value: 2 }.
// Drop val RefCell { value: 1 }.
// ---Drop dlink list---
// Drop head or tail.
// Drop head or tail.
fn dlink_list_drop_remove_reverse_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);
    assert_eq!(3, l.len());

    l.remove_first();
    l.remove_first();
    l.remove_first();
    assert_eq!(0, l.len());
}

#[test]
///---Drop dlink list---
// Drop val RefCell { value: 1 }.
// Drop val RefCell { value: 2 }.
// Drop val RefCell { value: 0 }.
// Drop head or tail.
// Drop head or tail.
fn dlink_list_head_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    let h = l.get_first();
    let mut t = 1;
    t = t + h.take();

    assert_eq!(4, t);
    assert_eq!(0, h.borrow().clone());
}

#[test]
fn dlink_list_iter() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    let mut iter = l.into_iter();

    dbg!(&iter);
    assert_eq!(iter.next().unwrap().take(), 3);
    assert_eq!(iter.next().unwrap().take(), 2);
    assert_eq!(iter.next().unwrap().take(), 1);
}

use rust_libs::dlink_list::DLinkList;

#[test]
fn dlink_list_insert_test() {
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
fn dlink_list_remove_test() {
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
fn dlink_list_remove_reverse_test() {
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
fn dlink_list_get_test() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    assert_eq!(3, l.peek_first().take());
    assert_eq!(1, l.peek_last().take());
}

#[test]
fn dlink_list_iter() {
    let mut l: DLinkList<i32> = DLinkList::new();
    l.insert_first(1);
    l.insert_first(2);
    l.insert_first(3);

    let mut iter = l.into_iter();

    assert_eq!(iter.next().unwrap().replace(3), 3);
    assert_eq!(iter.next().unwrap().replace(2), 2);
    assert_eq!(iter.next().unwrap().replace(1), 1);
}


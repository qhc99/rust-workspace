/// #839
pub fn num_similar_groups(strs: Vec<String>) -> i32 {
    let mut group = (0..strs.len()).map(|i| (i, 0usize)).collect::<Vec<_>>();
    for i in 0..strs.len() {
        let si = strs[i].as_str();
        for j in i + 1..strs.len() {
            let sj = strs[j].as_str();
            if is_str_similar(si, sj) {
                union(&mut group, i, j);
            }
        }
    }
    let mut arr = (0..group.len())
        .map(|idx| find(&mut group, idx))
        .collect::<Vec<_>>();
    arr.sort();
    arr.dedup();
    arr.len() as i32
}

fn find(arr: &mut [(usize, usize)], i: usize) -> usize {
    if arr[i].0 != i {
        arr[i].0 = find(arr, arr[i].0);
    }
    arr[i].0
}

fn union(arr: &mut [(usize, usize)], i: usize, j: usize) {
    let pi = find(arr, i);
    let pj = find(arr, j);
    if arr[pi].1 <= arr[pj].1 {
        arr[pi].0 = pj;
    } else {
        arr[pj].0 = pi;
    }
    if arr[pi].1 == arr[pj].1 {
        arr[pj].1 += 1;
    }
}

fn is_str_similar(a: &str, b: &str) -> bool {
    let mut i = 0;
    let mut diff = [0; 2];
    if a.len() != b.len() {
        return false;
    }
    for (idx, (c1, c2)) in a.chars().zip(b.chars()).enumerate() {
        if c1 != c2 {
            if i >= 2 {
                return false;
            }
            diff[i] = idx;
            i += 1
        }
    }
    return i == 0
        || (a.chars().nth(diff[0]) == b.chars().nth(diff[1])
            && a.chars().nth(diff[1]) == b.chars().nth(diff[0]));
}

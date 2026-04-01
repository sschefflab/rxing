// Custom serialization for Vec<F> where F: PrimeField - convert each field element to a
// decimal string. ark field types don't implement serde::Serialize, so we represent each
// element as its canonical decimal integer string.
pub fn serialize_fr_vec<F, S>(
    elems: &[F],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    F: ark_ff::PrimeField,
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    let mut seq = serializer.serialize_seq(Some(elems.len()))?;
    for elem in elems {
        seq.serialize_element(&elem.into_bigint().to_string())?;
    }
    seq.end()
}

// Custom serialization for BitMatrix - convert to 2D array of 0s and 1s
// Stored as rows[y][x] where each value is 0 (white) or 1 (black)
pub fn serialize_bitmatrix<S>(
    matrix: &crate::common::BitMatrix,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    let width = matrix.getWidth();
    let height = matrix.getHeight();

    // Create outer sequence for rows
    let mut rows = serializer.serialize_seq(Some(height as usize))?;
    for y in 0..height {
        // Build each row as a Vec<u8> of 0s and 1s
        let row: Vec<u8> = (0..width)
            .map(|x| if matrix.get(x, y) { 1 } else { 0 })
            .collect();
        rows.serialize_element(&row)?;
    }
    rows.end()
}

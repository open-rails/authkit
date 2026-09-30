package iam

// Shared operation inputs and results, importable without the engine.

// MaxBatch is the most ids (users, groups, subjects) one AuthKit query reads.
// Batch reads take any number and read them MaxBatch at a time.
const MaxBatch = 500

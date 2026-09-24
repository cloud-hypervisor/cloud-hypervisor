// Copyright © 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdlib.h>

#include <qpl/qpl.h>

#define QPL_SHIM_ALLOC_ERROR (-3)

struct qpl_shim {
    uint8_t *job_buffer;
    qpl_job *job;
};

int qpl_shim_create(uint32_t execution_path, struct qpl_shim **result) {
    struct qpl_shim *context = calloc(1, sizeof(*context));
    if (context == NULL) {
        return QPL_SHIM_ALLOC_ERROR;
    }

    uint32_t job_size = 0;
    qpl_status status = qpl_get_job_size((qpl_path_t)execution_path, &job_size);
    if (status != QPL_STS_OK) {
        free(context);
        return (int)status;
    }
    context->job_buffer = calloc(1, job_size);
    if (context->job_buffer == NULL) {
        free(context);
        return QPL_SHIM_ALLOC_ERROR;
    }
    context->job = (qpl_job *)context->job_buffer;
    status = qpl_init_job((qpl_path_t)execution_path, context->job);
    if (status != QPL_STS_OK) {
        free(context->job_buffer);
        free(context);
        return (int)status;
    }
    *result = context;
    return QPL_STS_OK;
}

uint32_t qpl_shim_compression_bound(struct qpl_shim *context, uint32_t input_size) {
    (void)context;
    return qpl_get_safe_deflate_compression_buffer_size(input_size);
}

int qpl_shim_compress(struct qpl_shim *context, const uint8_t *input,
                      uint32_t input_size, uint8_t *output,
                      uint32_t output_capacity, uint32_t *output_size,
                      uint32_t dynamic_huffman) {
    qpl_job *job = context->job;
    job->op = qpl_op_compress;
    job->level = qpl_default_level;
    job->next_in_ptr = (uint8_t *)input;
    job->available_in = input_size;
    job->total_in = 0;
    job->next_out_ptr = output;
    job->available_out = output_capacity;
    job->total_out = 0;
    job->flags = QPL_FLAG_FIRST | QPL_FLAG_LAST | QPL_FLAG_OMIT_VERIFY;
    if (dynamic_huffman) {
        job->flags |= QPL_FLAG_DYNAMIC_HUFFMAN;
    }
    qpl_status status = qpl_execute_job(job);
    if (status == QPL_STS_OK) {
        *output_size = job->total_out;
    }
    return (int)status;
}

int qpl_shim_submit_compress(struct qpl_shim *context, const uint8_t *input,
                             uint32_t input_size, uint8_t *output,
                             uint32_t output_capacity,
                             uint32_t dynamic_huffman) {
    qpl_job *job = context->job;
    job->op = qpl_op_compress;
    job->level = qpl_default_level;
    job->next_in_ptr = (uint8_t *)input;
    job->available_in = input_size;
    job->total_in = 0;
    job->next_out_ptr = output;
    job->available_out = output_capacity;
    job->total_out = 0;
    job->flags = QPL_FLAG_FIRST | QPL_FLAG_LAST | QPL_FLAG_OMIT_VERIFY;
    if (dynamic_huffman) {
        job->flags |= QPL_FLAG_DYNAMIC_HUFFMAN;
    }
    return (int)qpl_submit_job(job);
}

int qpl_shim_decompress(struct qpl_shim *context, const uint8_t *input,
                        uint32_t input_size, uint8_t *output,
                        uint32_t output_capacity, uint32_t *output_size) {
    qpl_job *job = context->job;
    job->op = qpl_op_decompress;
    job->next_in_ptr = (uint8_t *)input;
    job->available_in = input_size;
    job->total_in = 0;
    job->next_out_ptr = output;
    job->available_out = output_capacity;
    job->total_out = 0;
    job->flags = QPL_FLAG_FIRST | QPL_FLAG_LAST;
    qpl_status status = qpl_execute_job(job);
    if (status == QPL_STS_OK) {
        *output_size = job->total_out;
    }
    return (int)status;
}

int qpl_shim_submit_decompress(struct qpl_shim *context,
                               const uint8_t *input, uint32_t input_size,
                               uint8_t *output, uint32_t output_capacity) {
    qpl_job *job = context->job;
    job->op = qpl_op_decompress;
    job->next_in_ptr = (uint8_t *)input;
    job->available_in = input_size;
    job->total_in = 0;
    job->next_out_ptr = output;
    job->available_out = output_capacity;
    job->total_out = 0;
    job->flags = QPL_FLAG_FIRST | QPL_FLAG_LAST;
    return (int)qpl_submit_job(job);
}

int qpl_shim_check(struct qpl_shim *context, uint32_t *output_size) {
    qpl_status status = qpl_check_job(context->job);
    if (status == QPL_STS_OK) {
        *output_size = context->job->total_out;
    }
    return (int)status;
}

int qpl_shim_wait(struct qpl_shim *context) {
    return (int)qpl_wait_job(context->job);
}

void qpl_shim_destroy(struct qpl_shim *context) {
    if (context == NULL) {
        return;
    }
    qpl_fini_job(context->job);
    free(context->job_buffer);
    free(context);
}
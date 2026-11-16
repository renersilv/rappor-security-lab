#!/usr/bin/env python3
"""Compact model output preserves the existing candidate repair authority."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('candidate_patches', Path(__file__).resolve().parents[1] / 'candidate-repair-sandbox.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def bound(text):
    return dict(content=text, sha256=hashlib.sha256(text.encode()).hexdigest())


class CompactPatchTests(unittest.TestCase):
    def setUp(self):
        self.sources = {'source/value.mjs': bound('export const value = 1;\nexport const other = 2;\n')}
        self.proposal = dict(disposition='repair', diagnosis='Correct the synthetic value with an exact small change.', files=[
            dict(path='source/value.mjs', patches=[dict(before='value = 1', after='value = 3')]),
            dict(path='tests/repair-value.test.mjs', content="import test from 'node:test'; import assert from 'node:assert/strict'; import {value} from '../source/value.mjs'; test('value',()=>assert.equal(value,3));\n")])

    def test_exact_patch_materializes_full_source_then_reuses_existing_validator(self):
        before = copy.deepcopy(self.sources)
        result = S.expand_proposal(self.proposal, self.sources)
        edits, tests = S.validate_proposal(result, self.sources)
        self.assertEqual(edits[0]['content'], 'export const value = 3;\nexport const other = 2;\n')
        self.assertEqual(tests, [self.proposal['files'][1]])
        self.assertEqual(self.sources, before)
        self.assertIn('patches', self.proposal['files'][0])

    def test_multiple_patches_bind_original_positions_independently_of_order(self):
        self.proposal['files'][0]['patches'] = [dict(before='other = 2', after='other = 888'), dict(before='value = 1', after='value = 99')]
        result = S.expand_proposal(self.proposal, self.sources)
        self.assertEqual(result['files'][0]['content'], 'export const value = 99;\nexport const other = 888;\n')

    def test_absent_ambiguous_and_overlapping_matches_are_rejected(self):
        for source, patches in [
            ('value = 1; value = 1;', [dict(before='value = 1', after='fixed')]),
            ('aaaa', [dict(before='aaa', after='fixed')]),
            ('value = 1', [dict(before='missing', after='fixed')]),
            ('value = 1', [dict(before='value = 1', after='fixed'), dict(before='= 1', after='= 2')]),
        ]:
            with self.subTest(source=source, patches=patches):
                self.sources['source/value.mjs'] = bound(source)
                self.proposal['files'][0]['patches'] = patches
                with self.assertRaises(ValueError): S.expand_proposal(self.proposal, self.sources)

    def test_full_existing_source_output_and_patched_new_test_are_rejected(self):
        self.proposal['files'][0] = dict(path='source/value.mjs', content='export const value = 3;')
        with self.assertRaisesRegex(ValueError, 'patch-source'): S.expand_proposal(self.proposal, self.sources)
        self.setUp()
        self.proposal['files'][1] = dict(path='tests/repair-value.test.mjs', patches=[dict(before='old', after='new')])
        with self.assertRaisesRegex(ValueError, 'new-test-content'): S.expand_proposal(self.proposal, self.sources)

    def test_existing_test_assertions_remain_immutable_after_materialization(self):
        text = "import test from 'node:test';\nconst makeSnapshots = () => 1;\nconst observation = {};\ntest('value',()=>assert.equal(1,1));\n"
        self.sources['source/value.test.mjs'] = bound(text)
        self.proposal['files'].append(dict(path='source/value.test.mjs', patches=[dict(before='assert.equal(1,1)', after='assert.equal(1,2)')]))
        with self.assertRaisesRegex(ValueError, 'existing-test-changed'): S.expand_proposal(self.proposal, self.sources)

    def test_limits_source_hash_and_outside_paths_remain_enforced(self):
        for mutation in ('size', 'source_hash', 'outside', 'empty_before', 'same_before_after'):
            self.setUp()
            with self.subTest(mutation=mutation):
                if mutation == 'size': self.proposal['files'][1]['content'] = 'x' * 20001
                if mutation == 'source_hash': self.sources['source/value.mjs']['sha256'] = '0' * 64
                if mutation == 'outside': self.proposal['files'][0]['path'] = '../outside.mjs'
                if mutation == 'empty_before': self.proposal['files'][0]['patches'][0]['before'] = ''
                if mutation == 'same_before_after': self.proposal['files'][0]['patches'][0]['after'] = 'value = 1'
                with self.assertRaises(ValueError): S.expand_proposal(self.proposal, self.sources)

    def test_large_unchanged_source_does_not_inflate_model_response(self):
        source = '// unchanged implementation context\n' * 4000 + 'export const value = 1;\n'
        self.sources['source/value.mjs'] = bound(source)
        result = S.expand_proposal(self.proposal, self.sources)
        self.assertGreater(len(result['files'][0]['content']), 100000)
        self.assertLess(len(json.dumps(self.proposal)), 1000)
        self.assertEqual(result['files'][0]['content'], source.replace('value = 1', 'value = 3'))


if __name__ == '__main__':
    unittest.main()

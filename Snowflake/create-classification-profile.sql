CREATE OR REPLACE SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_PROFILE
  PB_DATA_CLASSIFICATION.DEFAULT_CLASSIFICATION_POLICY(
      {
        'minimum_object_age_for_classification_days': 0,
        'maximum_classification_validity_days': 365,
        'auto_tag': false,
        'classify_views': true
      });

--CREATE OR REPLACE SNOWFLAKE.DATA_PRIVACY.CUSTOM_CLASSIFIER PB_DATA_CLASSIFICATION.medical_codes(); --This is just a sample/test
--CALL PB_DATA_CLASSIFICATION.medical_codes!ADD_REGEX(
--  'ICD_10_CODES',
--  'IDENTIFIER',
--  '[A-TV-Z][0-9][0-9AB]\.?[0-9A-TV-Z]{0,4}',
--  'ICD.*',
--  'Add a regex to identify ICD-10 medical codes in a column',
--  0.8
--);


ALTER DATABASE PB_DATABASE
  SET CLASSIFICATION_PROFILE = 'PB_DATA_CLASSIFICATION.DEFAULT_CLASSIFICATION_POLICY';

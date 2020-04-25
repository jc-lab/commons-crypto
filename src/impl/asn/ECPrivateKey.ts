import * as asn1js from 'asn1js';
import * as pvutils from 'pvutils';
import { getParametersValue, toBase64, arrayBufferToString, stringToArrayBuffer, fromBase64 } from 'pvutils';
import ECPublicKey from './ECPublicKey';
const clearProps = (pvutils as any).clearProps;

//**************************************************************************************
/**
 * Class from RFC5915
 */
export default class ECPrivateKey
{
  version!: asn1js.Integer;
  namedCurve!: string;
  algorithmParams: asn1js.Any | null = null;
  privateKey!: asn1js.OctetString;
  publicKey!: ECPublicKey;

  coordinateLength: number = 0;

  //**********************************************************************************
  /**
   * Constructor for ECPrivateKey class
   * @param {Object} [parameters={}]
   * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
   */
  constructor(parameters: {
    coordinateLength?: number,
    version?: asn1js.Integer,
    namedCurve?: string,
    algorithmParams?: asn1js.Any,
    privateKey?: asn1js.OctetString,
    publicKey?: asn1js.BitString,
    schema?: any,
    json?: any
  } = {})
  {
    //region Internal properties of the object

    if (parameters && parameters['coordinateLength']) {
      this.coordinateLength = parameters.coordinateLength;
    }

    /**
     * @type {number}
     * @desc version
     */
    this.version = getParametersValue(parameters, 'version', ECPrivateKey.defaultValues('version'));
    /**
     * @type {OctetString}
     * @desc privateKey
     */
    this.privateKey = getParametersValue(parameters, 'privateKey', ECPrivateKey.defaultValues('privateKey'));
    /**
     * @type {Any}
     * @desc algorithmParams
     */
    this.algorithmParams = getParametersValue(parameters, 'algorithmParams', ECPrivateKey.defaultValues('algorithmParams'));
    if (this.algorithmParams instanceof asn1js.ObjectIdentifier) {
      this.namedCurve = this.algorithmParams.valueBlock.toString();
    } else {
      if ('namedCurve' in parameters) {
        /**
         * @type {string}
         * @desc namedCurve
         */
        this.namedCurve = getParametersValue(parameters, 'namedCurve', ECPrivateKey.defaultValues('namedCurve'));
      }
    }
    if ('publicKey' in parameters)
      /**
       * @type {ECPublicKey}
       * @desc publicKey
       */
      this.publicKey = getParametersValue(parameters, 'publicKey', ECPrivateKey.defaultValues('publicKey'));
    //endregion

    //region If input argument array contains "schema" for this object
    if ('schema' in parameters)
      this.fromSchema(parameters.schema);
    //endregion
    //region If input argument array contains "json" for this object
    if ('json' in parameters)
      this.fromJSON(parameters.json);
    //endregion
  }
  //**********************************************************************************
  /**
   * Return default values for all class members
   * @param {string} memberName String name for a class member
   */
  static defaultValues(memberName): any
  {
    switch (memberName)
    {
    case 'version':
      return 1;
    case 'privateKey':
      return new asn1js.OctetString();
    case 'namedCurve':
      return '';
    case 'algorithmParams':
      return null;
    case 'publicKey':
      return new ECPublicKey();
    default:
      throw new Error(`Invalid member name for ECCPrivateKey class: ${memberName}`);
    }
  }
  //**********************************************************************************
  /**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */
  static compareWithDefault(memberName, memberValue)
  {
    switch (memberName)
    {
    case 'version':
      return (memberValue === ECPrivateKey.defaultValues(memberName));
    case 'privateKey':
      return (memberValue.isEqual(ECPrivateKey.defaultValues(memberName)));
    case 'namedCurve':
      return (memberValue === '');
    case 'publicKey':
      return ((ECPublicKey.compareWithDefault('namedCurve', memberValue.namedCurve)) &&
          (ECPublicKey.compareWithDefault('x', memberValue.x)) &&
          (ECPublicKey.compareWithDefault('y', memberValue.y)));
    default:
      throw new Error(`Invalid member name for ECCPrivateKey class: ${memberName}`);
    }
  }
  //**********************************************************************************
  /**
   * Return value of pre-defined ASN.1 schema for current class
   *
   * ASN.1 schema:
   * ```asn1
   * ECPrivateKey ::= SEQUENCE {
   * version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
   * privateKey     OCTET STRING,
   * parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
   * publicKey  [1] BIT STRING OPTIONAL
   * }
   * ```
   *
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */
  static schema(parameters = {})
  {
    /**
     * @type {Object}
     * @property {string} [blockName]
     * @property {string} [version]
     * @property {string} [privateKey]
     * @property {string} [namedCurve]
     * @property {string} [publicKey]
     */
    const names: any = getParametersValue(parameters, 'names', {});

    return (new asn1js.Sequence({
      name: (names.blockName || ''),
      value: [
        new asn1js.Integer({ name: (names.version || '') } as any),
        new asn1js.OctetString({ name: (names.privateKey || '') } as any),
        new asn1js.Constructed({
          optional: true,
          idBlock: {
            tagClass: 3, // CONTEXT-SPECIFIC
            tagNumber: 0 // [0]
          },
          value: [
            new asn1js.Any({ name: (names.algorithmParams || '') } as any)
          ]
        } as any),
        new asn1js.Constructed({
          optional: true,
          idBlock: {
            tagClass: 3, // CONTEXT-SPECIFIC
            tagNumber: 1 // [1]
          },
          value: [
            new asn1js.BitString({ name: (names.publicKey || '') } as any)
          ]
        } as any)
      ]
    } as any));
  }
  //**********************************************************************************
  /**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
  fromSchema(schema)
  {
    //region Clear input data first
    clearProps(schema, [
      'version',
      'privateKey',
      'namedCurve',
      'algorithmParams',
      'publicKey'
    ]);
    //endregion

    //region Check the schema is valid
    const asn1 = asn1js.compareSchema(schema,
      schema,
      ECPrivateKey.schema({
        names: {
          version: 'version',
          privateKey: 'privateKey',
          algorithmParams: 'algorithmParams',
          publicKey: 'publicKey'
        }
      })
    );

    if (asn1.verified === false)
      throw new Error('Object\'s schema was not verified against input data for ECPrivateKey');
    //endregion

    //region Get internal properties from parsed schema
    this.version = asn1.result.version.valueBlock.valueDec;
    this.privateKey = asn1.result.privateKey;

    this.namedCurve = '';
    this.algorithmParams = null;
    if (asn1.result['algorithmParams']) {
      const algorithmParams = asn1.result.algorithmParams;
      if (algorithmParams instanceof asn1js.ObjectIdentifier) {
        this.namedCurve = algorithmParams.valueBlock.toString();
      } else {
        this.algorithmParams = algorithmParams;
      }
    }

    if ('publicKey' in asn1.result)
    {
      const publicKeyData: any = {
        coordinateLength: this.coordinateLength,
        schema: asn1.result.publicKey.valueBlock.valueHex
      };
      if ('namedCurve' in this)
        publicKeyData.namedCurve = this.namedCurve;

      this.publicKey = new ECPublicKey(publicKeyData);
    }
    //endregion
  }
  //**********************************************************************************
  /**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */
  toSchema()
  {
    const outputArray: any[] = [
      new asn1js.Integer({ value: this.version } as any),
      this.privateKey
    ];

    if (this['namedCurve'])
    {
      outputArray.push(new asn1js.Constructed({
        idBlock: {
          tagClass: 3, // CONTEXT-SPECIFIC
          tagNumber: 0 // [0]
        },
        value: [
          new asn1js.ObjectIdentifier({ value: this.namedCurve })
        ]
      } as any));
    } else {
      if (this.algorithmParams) {
        outputArray.push(new asn1js.Constructed({
          idBlock: {
            tagClass: 3, // CONTEXT-SPECIFIC
            tagNumber: 0 // [0]
          },
          value: [
            this.algorithmParams
          ]
        } as any));
      }
    }

    if ('publicKey' in this)
    {
      outputArray.push(new asn1js.Constructed({
        idBlock: {
          tagClass: 3, // CONTEXT-SPECIFIC
          tagNumber: 1 // [1]
        },
        value: [
          new asn1js.BitString({ valueHex: this.publicKey.toSchema().toBER(false) })
        ]
      } as any));
    }

    return new asn1js.Sequence({
      value: outputArray
    } as any);
  }
  //**********************************************************************************
  /**
   * Convertion for the class to JSON object
   * @returns {Object}
   */
  toJSON()
  {
    if ((('namedCurve' in this) === false) || (ECPrivateKey.compareWithDefault('namedCurve', this.namedCurve)))
      throw new Error('Not enough information for making JSON: absent "namedCurve" value');

    let crvName = '';

    switch (this.namedCurve)
    {
    case '1.2.840.10045.3.1.7': // P-256
      crvName = 'P-256';
      break;
    case '1.3.132.0.34': // P-384
      crvName = 'P-384';
      break;
    case '1.3.132.0.35': // P-521
      crvName = 'P-521';
      break;
    default:
    }

    const privateKeyJSON: any = {
      crv: crvName,
      d: (toBase64 as any)(arrayBufferToString(this.privateKey.valueBlock.valueHex), true, true, false)
    };

    if ('publicKey' in this)
    {
      const publicKeyJSON = this.publicKey.toJSON();

      privateKeyJSON.x = publicKeyJSON.x;
      privateKeyJSON.y = publicKeyJSON.y;
    }

    return privateKeyJSON;
  }
  //**********************************************************************************
  /**
   * Convert JSON value into current object
   * @param {Object} json
   */
  fromJSON(json)
  {
    let coodinateLength = 0;

    if ('crv' in json)
    {
      switch (json.crv.toUpperCase())
      {
      case 'P-256':
        this.namedCurve = '1.2.840.10045.3.1.7';
        coodinateLength = 32;
        break;
      case 'P-384':
        this.namedCurve = '1.3.132.0.34';
        coodinateLength = 48;
        break;
      case 'P-521':
        this.namedCurve = '1.3.132.0.35';
        coodinateLength = 66;
        break;
      default:
      }
    }
    else
      throw new Error('Absent mandatory parameter "crv"');

    if ('d' in json)
    {
      const convertBuffer = stringToArrayBuffer(fromBase64(json.d, true));

      if (convertBuffer.byteLength < coodinateLength)
      {
        const buffer = new ArrayBuffer(coodinateLength);
        const view = new Uint8Array(buffer);
        const convertBufferView = new Uint8Array(convertBuffer);
        view.set(convertBufferView, 1);

        this.privateKey = new asn1js.OctetString({ valueHex: buffer });
      }
      else
        this.privateKey = new asn1js.OctetString({ valueHex: convertBuffer.slice(0, coodinateLength) });
    }
    else
      throw new Error('Absent mandatory parameter "d"');

    if (('x' in json) && ('y' in json))
      this.publicKey = new ECPublicKey({ json });
  }
  //**********************************************************************************
}
//**************************************************************************************

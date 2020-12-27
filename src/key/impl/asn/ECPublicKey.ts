import {
  utilConcatBuf
} from 'pvutils';

import * as curves from '../curves';

import {ECParametersChoice} from './ECParameters';

export class ECPublicKey
{
  public x!: ArrayBuffer;
  public y!: ArrayBuffer;
  public coordinateLength: number = 0;
  public namedCurve: string = '';
  public algorithmParams?: ECParametersChoice;

  constructor(options: Partial<ECPublicKey> & {
    bitstream?: ArrayBuffer
  })
  {
    if (options.coordinateLength) {
      this.coordinateLength = options.coordinateLength;
    }
    if (options.algorithmParams) {
      this.algorithmParams = options.algorithmParams;
    }
    if (options.namedCurve) {
      this.namedCurve = options.namedCurve;
    } else if (this.algorithmParams && this.algorithmParams.namedCurve) {
      this.namedCurve = this.algorithmParams.namedCurve;
    }

    if (options.x) {
      this.x = options.x;
    }
    if (options.y) {
      this.y = options.y;
    }

    if ('bitstream' in options && options.bitstream) {
      this.fromBitStream(options.bitstream);
    }
  }

  fromBitStream(data: ArrayBuffer)
  {
    //region Check the schema is valid
    if (!(data instanceof ArrayBuffer))
      throw new Error('Object\'s schema was not verified against input data for ECPublicKey');

    const view = new Uint8Array(data);
    if (view[0] !== 0x04)
      throw new Error('Object\'s schema was not verified against input data for ECPublicKey');
    //endregion

    //region Get internal properties from parsed schema
    let coordinateLength = this.coordinateLength;

    if (!coordinateLength) {
      const curve = curves.getCurveByOid(this.namedCurve);
      if (curve) {
        coordinateLength = curve.options.byteLength;
      } else {
        throw new Error(`Incorrect curve OID: ${this.namedCurve}`);
      }
    }

    if (data.byteLength !== (coordinateLength * 2 + 1))
      throw new Error('Object\'s schema was not verified against input data for ECPublicKey');

    this.x = data.slice(1, coordinateLength + 1);
    this.y = data.slice(1 + coordinateLength, coordinateLength * 2 + 1);
  }

  toBitStream()
  {
    return utilConcatBuf(
      (new Uint8Array([0x04])).buffer,
      this.x,
      this.y
    );
  }
}
//**************************************************************************************

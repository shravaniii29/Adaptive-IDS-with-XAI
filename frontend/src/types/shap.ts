export interface ShapFeature {
  feature?: string;
  name?: string;
  value?: number;
  impact?: number;
}

export interface ShapExplanation {
  flow_id: string | number;
  top_features: (ShapFeature | string)[];
}
